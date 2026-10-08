using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NameserverBacktrackingTests
{
    [Fact]
    public async Task AuthenticatedUnsignedDependencyCannotBeReplacedByAnAncestorAddress()
    {
        using var fixture = new NameserverBacktrackingFixture();
        fixture.Source.UnsignedProvider = true;
        var record = new Mk8.Dns.Domain.DnsRecord(fixture.Source.Target, 1, 300, fixture.Source.Address);
        var keyQuestion = new Mk8.Dns.Domain.DnsQuestion(Mk8.Dns.Domain.DnsName.Parse("example."), 48, 1);
        var root = fixture.Source.Default(keyQuestion, NameserverDnssecFixture.RootServer);
        // Even signature-free forged address data must never become a route after the authenticated marker.
        fixture.AlternateReply = reply => reply.Question.Name.Equals(record.Owner) && reply.Question.Type == 1
            ? OnlineDnssecFixture.Reply(reply.Question, reply.Server, [record, root.Answers[^1]]) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(fixture.Source.ChildServer));
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Fact]
    public async Task AddressDependencyCanBacktrackToAnotherParentRoute()
    {
        using var fixture = new NameserverBacktrackingFixture();
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Single(result.Answers);
        Assert.Contains(fixture.Calls, call => call.Server.Equals(NameserverBacktrackingFixture.AlternateRoot) && call.Question.Name.Equals(fixture.Source.Target));
        Assert.Contains(fixture.Calls, call => call.Server.Equals(NameserverBacktrackingFixture.AlternateProvider) && call.Question.Type == 1);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type == 28);
    }

    [Fact]
    public async Task FailedBranchRoutingProofAndExpiredWindowCannotContaminateTheSuccessfulBranch()
    {
        using var fixture = new NameserverBacktrackingFixture { QueryFailsAfterAddress = true };
        fixture.Source.AddressTtl = 1; fixture.Source.AddressWindow = new DnssecSignatureWindow(99, 101);
        fixture.AfterFailure = () => fixture.Source.Clock.Advance(2);
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.True(result.AuthenticatedTtl > 1); Assert.True(Assert.Single(result.Answers).Ttl > 1);
        Assert.Contains(fixture.Calls, call => call.Server.Equals(NameserverBacktrackingFixture.ReplacementChild) && call.Question.Type == 48);
        Assert.All(result.Answers, record => Assert.Equal(NameserverDnssecFixture.Question.Name, record.Owner));
    }

    [Theory]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(12)]
    public async Task AddressBacktrackingSharesTheOriginalExchangeBudget(int limit)
    {
        using var fixture = new NameserverBacktrackingFixture();
        var result = await fixture.Resolver(exchanges: limit).ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Equal(limit, fixture.Calls.Count);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }
}
