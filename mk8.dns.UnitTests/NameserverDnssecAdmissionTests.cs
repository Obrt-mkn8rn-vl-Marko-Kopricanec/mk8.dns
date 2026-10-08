using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NameserverDnssecAdmissionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CorruptedAddressOrParentDsCannotAuthorizeChildTraffic(bool ds)
    {
        using var fixture = new NameserverDnssecFixture();
        fixture.Transform = reply => reply.Question.Type == (ds ? 43 : 1) && reply.Question.Name.Equals(ds ? DnsName.Parse("child.example.") : fixture.Target)
            ? OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Select(record =>
            {
                if (record.Type != 46) return record;
                var bytes = record.GetData(); bytes[^1] ^= 1; return new DnsRecord(record.Owner, 46, record.Ttl, bytes);
            }).ToArray()) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(fixture.ChildServer));
        if (ds) Assert.DoesNotContain(fixture.Calls, call => call.Question.Name.Equals(fixture.Target));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignedCnameOrDnameAtAnNsTargetIsNotAnAddress(bool dname)
    {
        using var fixture = new NameserverDnssecFixture();
        fixture.Override = (question, server, _) => ValueTask.FromResult(question.Name.Equals(fixture.Target) && server.Equals(NameserverDnssecFixture.ProviderServer)
            ? fixture.AliasReply(question, server, dname) : fixture.Default(question, server));
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(fixture.ChildServer) || call.Question.Name.Equals(DnsName.Parse("alternate.example.")));
    }

    [Theory]
    [InlineData("ns.other.")]
    [InlineData("*.example.")]
    public async Task UnsupportedTargetDoesNotLaunchAnAddressQuery(string target)
    {
        using var fixture = new NameserverDnssecFixture { Target = DnsName.Parse(target) };
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Name.Equals(fixture.Target));
    }

    [Fact]
    public async Task UnsignedRoutingDependencyDoesNotPromoteAMarkerOrFetchUnsignedData()
    {
        using var fixture = new NameserverDnssecFixture { UnsignedProvider = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Null(result.UnsignedDelegation);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => !call.Server.Equals(NameserverDnssecFixture.RootServer));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnicastEndpointAdmissionCannotBeBypassedByValidSignatures(bool multicast)
    {
        using var fixture = new NameserverDnssecFixture { Address = multicast ? [224, 0, 0, 1] : [0, 0, 0, 0] };
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.All(fixture.Calls, call => Assert.True(call.Server.Equals(NameserverDnssecFixture.RootServer) || call.Server.Equals(NameserverDnssecFixture.ProviderServer)));
    }

    [Fact]
    public async Task MissingInChildGlueDoesNotRecursivelyResolveTheSameChild()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => !reply.Authoritative ? OnlineDnssecFixture.Copy(reply, additional: []) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Name.Equals(DnsName.Parse("ns.child.example.")) || call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }
}
