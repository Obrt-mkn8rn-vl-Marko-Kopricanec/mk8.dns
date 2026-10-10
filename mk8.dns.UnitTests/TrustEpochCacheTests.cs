using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustEpochCacheTests
{
    [Fact]
    public async Task CurrentEpochHitUsesNeitherTransportNorVerifier()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        var first = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, first.Outcome);
        var calls = f.Calls.Count; var crypto = f.Verifier.Calls;
        var hit = await resolver.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("WWW.Example."), 1, 1), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(first.Answers[0].GetData(), hit.Answers[0].GetData());
        Assert.Equal(calls, f.Calls.Count); Assert.Equal(crypto, f.Verifier.Calls);
        Assert.Equal(1, resolver.Statistics.Entries); Assert.Equal(1, resolver.Statistics.Revision);
    }

    [Fact]
    public async Task IdenticalAnchorsAtNewAcknowledgedRevisionDiscardAllOldCachedData()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        f.LastOctet = 2;
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        var fresh = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, resolver.Statistics.Revision); Assert.Equal(1, resolver.Statistics.Anchors);
        Assert.Equal(2, Assert.Single(fresh.Answers).GetData()[3]); Assert.Equal(4, f.Calls.Count);
        Assert.Equal(1, resolver.Statistics.OwnedProfiles); Assert.Equal(0, resolver.Statistics.RetiredProfiles);
    }

    [Fact]
    public async Task ClearFencesStoresAndKeepsTheSameCommittedRevision()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        resolver.Clear(); Assert.Equal(0, resolver.Statistics.Entries); Assert.Equal(1, resolver.Statistics.Revision);
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(4, f.Calls.Count); Assert.Equal(1, resolver.Statistics.Entries);
    }

    [Fact]
    public async Task FailureHistoryIsReplacedAtEveryAcknowledgedRevision()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create(new DnssecTrustEpochPolicy(failureCache: new DnssecFailureCachePolicy(minimumTtl: 10, maximumTtl: 30)));
        f.Override = (_, _, _) => throw new IOException("Controlled contained transport refusal.");
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        var calls = f.Calls.Count;
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(calls, f.Calls.Count); Assert.Equal(1, resolver.Statistics.FailureEntries);
        await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true); f.Override = null;
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(0, resolver.Statistics.FailureEntries); Assert.Equal(calls + 2, f.Calls.Count);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    public async Task ZeroAndOversizeResultsDoNotBecomeReusableEpochEntries(uint ttl)
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); f.DataTtl = ttl;
        var resolver = f.Create(new DnssecTrustEpochPolicy(maximumPayloadBytes: 1));
        for (var count = 0; count < 2; count++)
            Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(4, f.Calls.Count); Assert.Equal(0, resolver.Statistics.Entries);
    }
}
