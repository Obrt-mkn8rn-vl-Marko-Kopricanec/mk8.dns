using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientResponseSelectionTests
{
    [Theory]
    [InlineData("www.example.", 1, false)]
    [InlineData("www.example.", 1, true)]
    [InlineData("www.example.", 28, false)]
    [InlineData("www.example.", 28, true)]
    [InlineData("missing.example.", 1, false)]
    [InlineData("missing.example.", 1, true)]
    public async Task RequestSelectsProofWithoutChangingOrdinaryResult(string name, int type, bool dnssecOk)
    {
        ArgumentNullException.ThrowIfNull(name);
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question(name, (ushort)type);
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        var sourceCalls = fixture.Calls.Count;
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var snapshot));
        Assert.Equal(question, snapshot.Question);
        Assert.Equal(result.ResponseCode, snapshot.ResponseCode);
        Assert.Equal(dnssecOk, snapshot.DnssecOk);
        Assert.Equal(fixture.Root, snapshot.Origin);
        Assert.Equal(result.AuthenticatedTtl, snapshot.RemainingTtl);
        Assert.Equal(sourceCalls, fixture.Calls.Count);
        Assert.Equal(dnssecOk, snapshot.Answers.Concat(snapshot.Authority).Any(record => record.Type == 46));
        Assert.Equal((dnssecOk && type != 1) || (dnssecOk && name.StartsWith("missing", StringComparison.Ordinal)),
            snapshot.Authority.Any(record => record.Type == 47));
        Assert.All(snapshot.Answers.Concat(snapshot.Authority), record => Assert.Equal(snapshot.RemainingTtl, record.Ttl));
        Assert.DoesNotContain(snapshot.Answers.Concat(snapshot.Authority), record => record.Type is 2 or 43 or 48);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExplicitDnskeyDataSurvivesDoSelection(bool dnssecOk)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = new DnsQuestion(fixture.Root, 48, 1);
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var snapshot));
        Assert.Equal(result.Answers.Count, snapshot.Answers.Count(record => record.Type == 48));
        Assert.Equal(dnssecOk, snapshot.Answers.Any(record => record.Type == 46));
        Assert.Empty(snapshot.Authority);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AliasAndNegativeTargetKeepClientSectionsAndSuppressInfrastructure(bool dnssecOk)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question("alias.example.");
        fixture.RootRecords.Add(new DnsRecord(question.Name, 5, 300, DnsName.Parse("missing.child.example.").ToWire()));
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var snapshot));
        Assert.Equal(3, snapshot.ResponseCode);
        Assert.Contains(snapshot.Answers, record => record.Type == 5 && record.Owner.Equals(question.Name));
        Assert.Contains(snapshot.Authority, record => record.Type == 6 && record.Owner.Equals(fixture.Child));
        Assert.DoesNotContain(snapshot.Answers.Concat(snapshot.Authority), record => record.Type is 2 or 43 or 48);
        Assert.Equal(dnssecOk, snapshot.Authority.Any(record => record.Type == 47));
    }
}
