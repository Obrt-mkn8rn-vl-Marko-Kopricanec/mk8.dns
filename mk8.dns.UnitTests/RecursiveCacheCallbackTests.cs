using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecursiveCacheCallbackTests
{
    private static readonly DnsQuestion Question = RecursiveCacheTests.Query("www.example.");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeadlineCancelsWaitersWithBlockedCallbackAndRetainsWorkerUntilBothFinish(bool callbackFinishesFirst)
    {
        var fixture = new RecursiveCacheCallbackFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var second = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        await fixture.Source.Registered.Task.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        fixture.Clock.Set(TimeSpan.FromSeconds(1));
        await AssertWaitersCanceledAsync(fixture, first, second).ConfigureAwait(true);
        Assert.Equal(2, (await fixture.Cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true)).ResponseCode);
        Assert.Equal(2, (await fixture.Cache.ResolveAsync(RecursiveCacheTests.Query("other.example."), CancellationToken.None).ConfigureAwait(true)).ResponseCode);
        Assert.Equal(1, fixture.Source.Calls);
        var drain = fixture.Cache.DisposeAsync().AsTask();
        await AssertDrainOwnedAsync(fixture, drain, callbackFinishesFirst).ConfigureAwait(true);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisposalCancelsWaitersWithBlockedCallbackAndJoinsCallbackAndProvider(bool callbackFinishesFirst)
    {
        var fixture = new RecursiveCacheCallbackFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var second = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        await fixture.Source.Registered.Task.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        var drain = fixture.Cache.DisposeAsync().AsTask();
        Assert.Same(drain, fixture.Cache.DisposeAsync().AsTask());
        await AssertWaitersCanceledAsync(fixture, first, second).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<ObjectDisposedException>(() => fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        await AssertDrainOwnedAsync(fixture, drain, callbackFinishesFirst).ConfigureAwait(true);
    }

    private static async Task AssertWaitersCanceledAsync(RecursiveCacheCallbackFixture fixture, Task<DnsAnswer> first, Task<DnsAnswer> second)
    {
        await fixture.Source.CallbackEntered.Task.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.False(fixture.Source.CallbackExited.Task.IsCompleted);
        // Both assertions run while the later provider callback still owns the dispatcher.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(TimeSpan.FromSeconds(2))).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second.WaitAsync(TimeSpan.FromSeconds(2))).ConfigureAwait(true);
        Assert.True(fixture.Source.Token.IsCancellationRequested);
        Assert.Equal(0, fixture.Cache.Statistics.Waiters);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(1, fixture.Clock.ActiveTimers);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
    }

    private static async Task AssertDrainOwnedAsync(RecursiveCacheCallbackFixture fixture, Task drain, bool callbackFinishesFirst)
    {
        Assert.False(drain.IsCompleted);
        if (callbackFinishesFirst)
        {
            fixture.Source.ReleaseCallback();
            await fixture.Source.CallbackExited.Task.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
            Assert.Equal(1, fixture.Clock.ActiveTimers);
        }
        else
        {
            fixture.Source.FinishProvider();
            await fixture.TimerDisposed.Task.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
            Assert.False(fixture.Source.CallbackExited.Task.IsCompleted);
            Assert.Equal(0, fixture.Clock.ActiveTimers);
        }
        Assert.False(drain.IsCompleted);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(0, fixture.Cache.Statistics.Waiters);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        fixture.Source.FinishProvider();
        fixture.Source.ReleaseCallback();
        await drain.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(0, fixture.Cache.Statistics.Waiters);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        Assert.Equal(0, fixture.Cache.Statistics.PayloadBytes);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
        Assert.True(fixture.Source.CallbackExited.Task.IsCompletedSuccessfully);
        Assert.True(fixture.TimerDisposed.Task.IsCompletedSuccessfully);
    }
}
