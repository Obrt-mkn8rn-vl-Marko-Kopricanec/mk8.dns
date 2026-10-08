using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthorityBacktrackingHierarchyTests
{
    [Theory]
    [InlineData(1, DnssecResolutionOutcome.Authenticated)]
    [InlineData(2, DnssecResolutionOutcome.Authenticated)]
    [InlineData(3, DnssecResolutionOutcome.Authenticated)]
    [InlineData(8, DnssecResolutionOutcome.Authenticated)]
    [InlineData(15, DnssecResolutionOutcome.Authenticated)]
    [InlineData(16, DnssecResolutionOutcome.Failure)]
    public async Task ADeepDeadEndCanUnwindEveryAncestorBeforeTheAlternateRootRoute(int cuts, DnssecResolutionOutcome expected)
    {
        using var source = new OnlineDnssecHierarchyFixture(cuts);
        var root = new DnsServerEndpoint([127, 0, 0, 1], 5300);
        var key = await source.ExchangeDnssecAsync(new DnsQuestion(DnsName.Parse("example."), 48, 1), root, CancellationToken.None);
        var upstream = new Branches(source, root, new DnsServerEndpoint([127, 0, 0, (byte)(cuts + 1)], 5300));
        var resolver = new DnssecIterativeResolver(upstream, DnssecFixture.Verifier, new DnssecTrustAnchor(key.Answers[0]),
            [root, Branches.Alternate], 5300, maximumExchanges: 256, time: new FixedClock());
        var result = await resolver.ResolveDnssecAsync(source.Question, CancellationToken.None);
        Assert.Equal(expected, result.Outcome);
        if (expected == DnssecResolutionOutcome.Authenticated) Assert.Single(result.Answers);
        else Assert.Empty(result.Answers);
        Assert.Equal(6 * cuts + (expected == DnssecResolutionOutcome.Authenticated ? 3 : 1), upstream.Calls);
        Assert.True(upstream.UsedAlternate);
    }

    private sealed class Branches(OnlineDnssecHierarchyFixture source, DnsServerEndpoint root, DnsServerEndpoint leaf) : IDnssecUpstream
    {
        internal static DnsServerEndpoint Alternate { get; } = new([127, 0, 0, 250], 5300);
        internal int Calls { get; private set; }
        internal bool UsedAlternate { get; private set; }
        public async ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            Calls++;
            if (server.Equals(Alternate)) UsedAlternate = true;
            if (server.Equals(leaf) && question.Type != 48 && !UsedAlternate) return null!;
            var reply = await source.ExchangeDnssecAsync(question, server.Equals(Alternate) ? root : server, cancellationToken).ConfigureAwait(false);
            return OnlineDnssecFixture.Copy(reply, server: server);
        }
    }
    private sealed class FixedClock : TimeProvider
    {
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
