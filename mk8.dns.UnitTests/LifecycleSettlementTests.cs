using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class LifecycleSettlementTests
{
    [Fact]
    public async Task IndependentSettlementsStartAndRetainBothOriginalFailures()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = new IOException("Controlled first cleanup failure.");
        var second = new InvalidOperationException("Controlled independent cleanup failure.");
        var actual = TestTaskSettlement.AllAsync(async () =>
        {
            await release.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            throw first;
        }, () =>
        {
            release.TrySetResult();
            throw second;
        });
        await TestTaskSettlement.RunAsync(async () =>
        {
            var error = await Assert.ThrowsAsync<AggregateException>(() => actual.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.Collection(error.InnerExceptions, e => Assert.Same(first, e), e => Assert.Same(second, e));
        }, async () =>
        {
            release.TrySetResult();
            var error = await Record.ExceptionAsync(() => actual.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
            var aggregate = Assert.IsType<AggregateException>(error);
            Assert.Collection(aggregate.InnerExceptions, e => Assert.Same(first, e), e => Assert.Same(second, e));
        }).ConfigureAwait(true);
    }

    [Fact]
    public async Task ExpiredObservationStillOwnsActualWorkAndRetainsItsLaterFailure()
    {
        var source = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failure = new IOException("Controlled failure after the observation deadline.");
        // Zero is a controlled observer input, not a change to any fixture guard.
        var observation = TestTaskSettlement.WaitAsync(source.Task.WaitAsync(CancellationToken.None), TimeSpan.Zero);
        await TestTaskSettlement.RunAsync(async () =>
        {
            Assert.False(observation.IsCompleted);
            source.SetException(failure);
            var error = await Assert.ThrowsAsync<AggregateException>(() => observation.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.IsType<TimeoutException>(error.InnerExceptions[0]);
            Assert.Same(failure, error.InnerExceptions[1]);
        }, async () =>
        {
            source.TrySetException(failure);
            await TestTaskSettlement.AllAsync(async () =>
                Assert.Same(failure, await Record.ExceptionAsync(() => source.Task.WaitAsync(CancellationToken.None)).ConfigureAwait(true)), async () =>
            {
                var error = await Record.ExceptionAsync(() => observation.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
                Assert.IsType<AggregateException>(error);
            }).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }

    [Fact]
    public async Task WorkTimerReleaseFailureCannotSkipActualManagedTimerRetirement()
    {
        var clock = new DnssecWorkTimerClock();
        var timer = clock.CreateTimer(_ => { }, state: null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        await CheckTimerAsync(timer, clock.DisposalEntered.Task.WaitAsync(CancellationToken.None),
            error => clock.DisposalReleased.TrySetException(error), () => clock.ActiveTimers).ConfigureAwait(true);
    }

    [Fact]
    public async Task CacheTimerReleaseFailureCannotSkipActualManagedTimerRetirement()
    {
        var fixture = new RecursiveCacheCallbackFixture(holdTimer: true);
        await using var lifetime = fixture.ConfigureAwait(true);
        var timer = fixture.TimerProvider.CreateTimer(_ => { }, state: null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        await CheckTimerAsync(timer, fixture.TimerDisposing.Task.WaitAsync(CancellationToken.None),
            error => fixture.TimerRelease.TrySetException(error), () => fixture.Clock.ActiveTimers).ConfigureAwait(true);
        Assert.True(fixture.TimerDisposed.Task.IsCompletedSuccessfully);
    }

    private static async Task CheckTimerAsync(ITimer timer, Task entered, Action<Exception> release, Func<int> activeTimers)
    {
        var failure = new IOException("Controlled timer release-observer failure.");
        var actual = timer.DisposeAsync().AsTask();
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, activeTimers());
            release(failure);
            Assert.Same(failure, await Assert.ThrowsAsync<IOException>(() => actual.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true));
            Assert.Equal(0, activeTimers());
        }, async () =>
        {
            release(failure);
            Assert.Same(failure, await Record.ExceptionAsync(() => actual.WaitAsync(CancellationToken.None)).ConfigureAwait(true));
        }).ConfigureAwait(true);
    }
}
