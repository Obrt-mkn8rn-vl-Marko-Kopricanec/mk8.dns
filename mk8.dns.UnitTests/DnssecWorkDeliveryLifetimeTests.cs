using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecWorkDeliveryLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharedDeliveryAgesDataAndRechecksSourceLeaseAfterHeldTimerCleanup(bool expire)
    {
        using var fixture = new OnlineDnssecFixture();
        var clock = new DnssecWorkTimerClock();
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var resolver = new CoalescingDnssecResolver(cache, new DnssecWorkPolicy(resolutionTimeout: TimeSpan.FromSeconds(10)), clock);
        await using var resolverLifetime = resolver.ConfigureAwait(true);
        var result = resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        try
        {
            await clock.DisposalEntered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
            if (expire) fixture.Clock.SetWall(10001);
            else { clock.Set(2); fixture.Clock.Advance(2); }
        }
        finally { clock.DisposalReleased.TrySetResult(); }
        var completed = await result.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(expire ? DnssecResolutionOutcome.Failure : DnssecResolutionOutcome.Authenticated, completed.Outcome);
        if (expire) { Assert.Empty(completed.Answers); Assert.Empty(completed.Authority); }
        else Assert.True(Assert.Single(completed.Answers).Ttl <= 298);
    }

    [Fact]
    public async Task WaiterDeadlineMustRemainIndependentWhileTimerDisposalIsHeld()
    {
        using var fixture = new OnlineDnssecFixture();
        var clock = new DnssecWorkTimerClock();
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var resolver = new CoalescingDnssecResolver(cache, new DnssecWorkPolicy(resolutionTimeout: TimeSpan.FromSeconds(1)), clock);
        await using var resolverLifetime = resolver.ConfigureAwait(true);
        var query = resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        try
        {
            await clock.DisposalEntered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
            clock.Set(1);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => query.WaitAsync(TimeSpan.FromSeconds(2))).ConfigureAwait(true);
            Assert.Equal(1, resolver.Statistics.Workers);
            Assert.Equal(0, resolver.Statistics.Waiters);
        }
        finally { clock.DisposalReleased.TrySetResult(); }
    }
}
