using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class FixtureCloseSettlementTests
{
    [Fact]
    public async Task ExpiredCloseGuardStillJoinsBeforeBorrowerAndRetainsBothFailures()
    {
        var actual = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failure = new IOException("Controlled close failure.");
        var borrowerRetired = false;
        var closing = TestTaskSettlement.InOrderAsync(
            () => TestTaskSettlement.WaitAsync(actual.Task.WaitAsync(CancellationToken.None), TimeSpan.Zero),
            () => { borrowerRetired = true; return Task.CompletedTask; });
        await TestTaskSettlement.RunAsync(async () =>
        {
            Assert.False(closing.IsCompleted); Assert.False(borrowerRetired);
            actual.SetException(failure);
            var error = await Assert.ThrowsAsync<AggregateException>(() => closing.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.IsType<TimeoutException>(error.InnerExceptions[0]); Assert.Same(failure, error.InnerExceptions[1]);
            Assert.True(borrowerRetired);
        }, async () =>
        {
            actual.TrySetException(failure);
            await TestTaskSettlement.AllAsync(
                () => TestTaskSettlement.ObserveAsync(actual.Task.WaitAsync(CancellationToken.None), error => ReferenceEquals(error, failure)),
                () => TestTaskSettlement.ObserveAsync(closing.WaitAsync(CancellationToken.None), error => error is AggregateException aggregate
                    && aggregate.InnerExceptions.Count == 2 && aggregate.InnerExceptions[0] is TimeoutException
                    && ReferenceEquals(aggregate.InnerExceptions[1], failure))).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }

    [Fact]
    public async Task ExpectedTerminalFailureDoesNotEraseAnIndependentExpiredGuard()
    {
        var actual = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failure = new KeyNotFoundException("Controlled expected result.");
        var closing = TestTaskSettlement.WaitAsync(actual.Task.WaitAsync(CancellationToken.None), TimeSpan.Zero, error => ReferenceEquals(error, failure));
        await TestTaskSettlement.RunAsync(async () =>
        {
            Assert.False(closing.IsCompleted); actual.SetException(failure);
            await Assert.ThrowsAsync<TimeoutException>(() => closing.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        }, async () =>
        {
            actual.TrySetException(failure);
            await TestTaskSettlement.AllAsync(
                () => TestTaskSettlement.ObserveAsync(actual.Task.WaitAsync(CancellationToken.None), error => ReferenceEquals(error, failure)),
                () => TestTaskSettlement.ObserveAsync(closing.WaitAsync(CancellationToken.None), error => error is TimeoutException)).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }

    [Fact]
    public async Task PollingTimerReleaseFaultCannotSkipItsActualManagedRetirement()
    {
        var fixture = new AnchorPollingFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        fixture.Clock.HoldDisposal = true;
        var timer = fixture.Clock.CreateTimer(_ => { }, state: null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        var failure = new IOException("Controlled timer release observer fault.");
        var closing = timer.DisposeAsync().AsTask();
        await TestTaskSettlement.RunAsync(async () =>
        {
            await fixture.Clock.DisposalEntered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, fixture.Clock.ActiveTimers);
            fixture.Clock.DisposalReleased.SetException(failure);
            Assert.Same(failure, await Record.ExceptionAsync(() => closing.WaitAsync(CancellationToken.None)).ConfigureAwait(true));
            Assert.Equal(0, fixture.Clock.ActiveTimers);
        }, async () =>
        {
            fixture.Clock.DisposalReleased.TrySetException(failure);
            await TestTaskSettlement.ObserveAsync(closing.WaitAsync(CancellationToken.None), error => ReferenceEquals(error, failure)).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }
}
