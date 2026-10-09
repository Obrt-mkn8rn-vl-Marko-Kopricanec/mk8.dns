using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecWorkFaultTests
{
    [Fact]
    public async Task ProviderFaultIsSharedAndDoesNotCreateAFailureCacheEntry()
    {
        var fixture = new DnssecWorkFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        var second = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        fixture.Fail();
        await Assert.ThrowsAsync<InvalidOperationException>(() => first.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => second.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Entries); Assert.Equal(0, fixture.Cache.FailureStatistics.Entries);
        Assert.Equal(0, fixture.Resolver.Statistics.Workers); Assert.Equal(0, fixture.Resolver.Statistics.Waiters);
    }

    [Fact]
    public async Task OwnedCancellationCallbackFaultIsJoinedAndReportedBySharedDisposal()
    {
        using var zones = new OnlineDnssecFixture();
        var clock = new RecursiveCacheClock();
        var registered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationTokenRegistration callback = default;
        zones.Override = (_, _, token) =>
        {
            callback = token.Register(() => throw new InvalidOperationException("Controlled cancellation cleanup fault."));
            registered.TrySetResult(); return new ValueTask<DnsUpstreamEvidence>(held.Task);
        };
        var cache = CachingDnssecResolver.CreateWithFailureCache(zones.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var resolver = new CoalescingDnssecResolver(cache, new DnssecWorkPolicy(resolutionTimeout: TimeSpan.FromSeconds(1)), clock);
        var query = resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await registered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        var drain = resolver.DisposeAsync().AsTask();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => query.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
            Assert.False(drain.IsCompleted);
        }
        finally
        {
            held.TrySetResult(zones.Default(new DnsQuestion(zones.Root, 48, 1), OnlineDnssecFixture.RootServer));
            await Assert.ThrowsAsync<InvalidOperationException>(() => drain.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
            await callback.DisposeAsync().ConfigureAwait(true);
        }
        Assert.Same(drain, resolver.DisposeAsync().AsTask());
        Assert.Equal(0, cache.FailureStatistics.Entries); Assert.Equal(0, cache.Statistics.Entries);
        Assert.Equal(0, resolver.Statistics.Workers); Assert.Equal(0, clock.ActiveTimers);
    }
}
