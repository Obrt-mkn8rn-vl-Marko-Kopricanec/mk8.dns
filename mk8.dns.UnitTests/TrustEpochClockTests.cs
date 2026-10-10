using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustEpochClockTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MonotonicAndForwardWallExpiryRequireNewAcquisition(bool wall)
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        if (wall) f.Anchors.Keys.Clock.SetWall(4000);
        else f.Anchors.Keys.Clock.SetMonotonic(4000);
        f.LastOctet = 2;
        var fresh = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome);
        Assert.Equal(2, Assert.Single(fresh.Answers).GetData()[3]); Assert.Equal(4, f.Calls.Count);
    }

    [Fact]
    public async Task NewEpochCannotResetTheRefresherHighWaterClocksToReviveExpiredEvidence()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        f.Anchors.Keys.Clock.SetWall(90000); f.Anchors.Keys.Clock.SetMonotonic(10);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        f.Anchors.Keys.Clock.SetWall(100); f.Anchors.Keys.Clock.SetMonotonic(0);
        var refused = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, refused.Outcome); Assert.Equal(2, resolver.Statistics.Revision);
        Assert.Equal(0, resolver.Statistics.Entries); Assert.Equal(3, f.Calls.Count);
        f.Anchors.Keys.Clock.SetWall(90001); f.Anchors.Keys.Clock.SetMonotonic(11);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
    }

    [Fact]
    public async Task AwaitedSourceTimeAlsoConservativelySpendsDeliveryTtl()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        f.Override = (question, server, _) =>
        {
            if (question.Type == 48) f.Anchors.Keys.Clock.Advance(30);
            return ValueTask.FromResult(f.Default(question, server));
        };
        var answer = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, answer.Outcome);
        Assert.InRange(answer.AuthenticatedTtl, 1u, 270u);
        Assert.All(answer.Answers, record => Assert.InRange(record.Ttl, 1u, 270u));
    }

    [Fact]
    public async Task CacheHitsAgeWholeAnswerAndCannotReviveOnMonotonicRollback()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        f.Anchors.Keys.Clock.SetMonotonic(10.1);
        var aged = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(289u, aged.AuthenticatedTtl);
        f.Anchors.Keys.Clock.SetMonotonic(0);
        var rollback = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(aged.AuthenticatedTtl, rollback.AuthenticatedTtl); Assert.Equal(2, f.Calls.Count);
    }
}
