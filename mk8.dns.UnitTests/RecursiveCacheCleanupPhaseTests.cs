using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecursiveCacheCleanupPhaseTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WaiterCancellationRemainsLiveWhileTimerDisposalIsHeld(bool close)
    {
        var fixture = new RecursiveCacheCallbackFixture(holdTimer: true);
        await using var lifetime = fixture.ConfigureAwait(true);
        var reply = fixture.Cache.ResolveAsync(RecursiveCacheTests.Query("www.example."), CancellationToken.None).AsTask();
        await fixture.Source.Registered.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        fixture.Source.FinishProvider();
        await fixture.TimerDisposing.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.False(reply.IsCompleted);
        if (close) _ = fixture.Cache.DisposeAsync().AsTask();
        else fixture.Clock.Set(TimeSpan.FromSeconds(1));
        await fixture.Source.CallbackEntered.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reply.WaitAsync(TimeSpan.FromSeconds(2), TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Waiters);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(1, fixture.Clock.ActiveTimers);
        var disposal = fixture.Cache.DisposeAsync().AsTask();
        Assert.False(disposal.IsCompleted);
        fixture.TimerRelease.TrySetResult();
        await fixture.TimerDisposed.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.False(disposal.IsCompleted);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveFlights);
        fixture.Source.ReleaseCallback();
        await disposal.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
    }

    [Fact]
    public async Task TimerFaultStillJoinsHeldDispatcherAndRetainsBothOriginalFaults()
    {
        var fixture = new RecursiveCacheCallbackFixture(holdTimer: true, failTimer: true);
        await using var lifetime = fixture.ConfigureAwait(true);
        var callbackFailure = new InvalidOperationException("Owned callback failure.");
        fixture.Source.CallbackFailure = callbackFailure;
        var reply = fixture.Cache.ResolveAsync(RecursiveCacheTests.Query("www.example."), CancellationToken.None).AsTask();
        await fixture.Source.Registered.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        fixture.Source.FinishProvider();
        await fixture.TimerDisposing.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var disposal = fixture.Cache.DisposeAsync().AsTask();
        await fixture.Source.CallbackEntered.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reply.WaitAsync(TimeSpan.FromSeconds(2), TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        fixture.TimerRelease.TrySetResult();
        await fixture.TimerDisposed.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.False(disposal.IsCompleted);
        Assert.False(fixture.Source.CallbackExited.Task.IsCompleted);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveFlights);
        fixture.Source.ReleaseCallback();
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => disposal.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        var combined = Assert.IsType<AggregateException>(failure.InnerException);
        Assert.Contains(fixture.TimerFailure, combined.Flatten().InnerExceptions);
        Assert.Contains(callbackFailure, combined.Flatten().InnerExceptions);
        Assert.Same(disposal, fixture.Cache.DisposeAsync().AsTask());
        Assert.True(fixture.Source.CallbackExited.Task.IsCompletedSuccessfully);
        Assert.Equal(0, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
    }
}
