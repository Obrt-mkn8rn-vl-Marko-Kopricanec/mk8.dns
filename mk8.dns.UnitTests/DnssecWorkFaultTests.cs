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
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var second = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        fixture.Fail();
        await Assert.ThrowsAsync<InvalidOperationException>(() => first.WaitAsync(DnssecWorkFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => second.WaitAsync(DnssecWorkFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Entries); Assert.Equal(0, fixture.Cache.FailureStatistics.Entries);
        Assert.Equal(0, fixture.Resolver.Statistics.Workers); Assert.Equal(0, fixture.Resolver.Statistics.Waiters);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OwnedCancellationCallbackFaultIsJoinedAndReportedBySharedDisposal(bool observerFailure)
    {
        using var zones = new OnlineDnssecFixture();
        var clock = new RecursiveCacheClock();
        var registered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackFault = new InvalidOperationException("Controlled cancellation cleanup fault.");
        CancellationTokenRegistration callback = default;
        zones.Override = (_, _, token) =>
        {
            callback = token.Register(() => throw callbackFault);
            registered.TrySetResult(); return new ValueTask<DnsUpstreamEvidence>(held.Task);
        };
        var cache = CachingDnssecResolver.CreateWithFailureCache(zones.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var resolver = new CoalescingDnssecResolver(cache, new DnssecWorkPolicy(resolutionTimeout: TimeSpan.FromSeconds(1)), clock);
        var query = resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        Task? drain = null;
        var observer = new IOException("Controlled registered-provider observer failure.");
        var observed = await Record.ExceptionAsync(() => TestTaskSettlement.RunAsync(async () =>
        {
            await registered.Task.WaitAsync(DnssecWorkFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            if (observerFailure) throw observer;
            drain = resolver.DisposeAsync().AsTask();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => query.WaitAsync(DnssecWorkFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.False(drain.IsCompleted);
        }, async () =>
        {
            drain ??= resolver.DisposeAsync().AsTask();
            held.TrySetResult(zones.Default(new DnsQuestion(zones.Root, 48, 1), OnlineDnssecFixture.RootServer));
            await TestTaskSettlement.RunAsync(async () => AssertCallbackFault(await Assert.ThrowsAsync<InvalidOperationException>(() => drain.WaitAsync(DnssecWorkFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true), callbackFault), async () =>
            {
                await TestTaskSettlement.RunAsync(async () =>
                {
                    var error = await Record.ExceptionAsync(() => drain.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
                    AssertCallbackFault(error, callbackFault);
                }, async () => await TestTaskSettlement.RunAsync(async () =>
                {
                    var error = await Record.ExceptionAsync(() => query.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
                    if (error is not OperationCanceledException) Assert.Null(error);
                }, async () => await callback.DisposeAsync().ConfigureAwait(true)).ConfigureAwait(true)).ConfigureAwait(true);
            }).ConfigureAwait(true);
        })).ConfigureAwait(true);
        if (observerFailure) Assert.Same(observer, observed);
        else Assert.Null(observed);
        Assert.Same(drain, resolver.DisposeAsync().AsTask());
        AssertRetired(cache, resolver, clock);
    }
    private static void AssertCallbackFault(Exception? error, Exception expected)
    {
        var wrapper = Assert.IsType<InvalidOperationException>(error);
        var dispatch = Assert.IsType<AggregateException>(wrapper.InnerException);
        Assert.Same(expected, Assert.Single(dispatch.Flatten().InnerExceptions));
    }

    private static void AssertRetired(CachingDnssecResolver cache, CoalescingDnssecResolver resolver, RecursiveCacheClock clock)
    {
        Assert.Equal(0, cache.FailureStatistics.Entries); Assert.Equal(0, cache.Statistics.Entries);
        Assert.Equal(0, resolver.Statistics.Workers); Assert.Equal(0, clock.ActiveTimers);
    }
}
