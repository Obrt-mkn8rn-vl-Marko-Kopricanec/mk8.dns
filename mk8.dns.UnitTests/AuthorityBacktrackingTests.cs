using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthorityBacktrackingTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task AuthenticatedDeadChildReturnsToTheNextParentEndpoint(int defect)
    {
        using var fixture = new AuthorityBacktrackingFixture();
        fixture.BadReply = (question, _) => defect switch
        {
            1 => throw new IOException("Owned branch failure."),
            2 => throw new FormatException("Owned malformed response."),
            3 => ValueTask.FromResult(OnlineDnssecFixture.Reply(question, AuthorityBacktrackingFixture.BadChild,
                [DnssecFixture.A(question.Name.ToString())])),
            _ => ValueTask.FromResult<DnsUpstreamEvidence>(null!),
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(Assert.Single(fixture.Source.ChildRecords).GetData(), Assert.Single(result.Answers).GetData());
        Assert.Equal(9, fixture.Calls.Count);
        Assert.Equal(1, fixture.Calls.Count(call => call.Server.Equals(AuthorityBacktrackingFixture.BadChild) && call.Question.Type == 1));
        Assert.Equal(1, fixture.Calls.Count(call => call.Server.Equals(AuthorityBacktrackingFixture.AlternateRoot) && call.Question.Type == 43));
    }

    [Fact]
    public async Task AllFailedBranchesReturnNoAccumulatedAliasData()
    {
        using var fixture = new AuthorityBacktrackingFixture();
        fixture.Source.RootRecords.Add(new DnsRecord(DnsName.Parse("alias.example."), 5, 300, AuthorityBacktrackingFixture.Question.Name.ToWire()));
        fixture.AlternateReply = reply => !reply.Authoritative ? OnlineDnssecFixture.Copy(reply,
            additional: reply.Additional.Select(record => new DnsRecord(record.Owner, record.Type, record.Ttl, AuthorityBacktrackingFixture.BadChild.GetAddress())).ToArray()) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("alias.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.Equal(2, fixture.Calls.Count(call => call.Question.Type == 1 && call.Server.Equals(AuthorityBacktrackingFixture.BadChild)));
    }
}
