using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CoalescedTrustEpochCleanupFaultTests
{
    [Fact]
    public async Task TimerAndHeldDispatcherFaultsRemainOwnedThroughRepeatedEpochDisposal()
    {
        var f = new CoalescedTrustEpochFixture(workers: 1); await using var lifetime = f.ConfigureAwait(true);
        var callback = new HeldCallback(); await using var callbackLifetime = callback.ConfigureAwait(true);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        var timerFailure = new IOException("Controlled authenticated timer failure.");
        f.Clock.HoldDisposal = true; f.Clock.DisposalFailure = timerFailure;
        f.Override = (_, _, token) => callback.ReadAsync(held.Task, token);
        var pending = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await TestTaskSettlement.RunAsync(() => ObserveDrainAsync(f, callback, pending.WaitAsync(CancellationToken.None), held, keys, timerFailure), async () =>
        {
            callback.Release(); held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server)); f.Clock.DisposalReleased.TrySetResult();
            f.ExpectedDisposalFailure = await Record.ExceptionAsync(() => f.Resolver.DisposeAsync().AsTask()).ConfigureAwait(true);
            var outcome = await Record.ExceptionAsync(() => pending.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
            if (outcome is not null and not OperationCanceledException && !(Contains(outcome, timerFailure) && Contains(outcome, callback.Failure)))
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(outcome).Throw();
        }).ConfigureAwait(true);
    }

    private static async Task ObserveDrainAsync(CoalescedTrustEpochFixture f, HeldCallback callback, Task pending,
        TaskCompletionSource<DnsUpstreamEvidence> held, DnsQuestion keys, IOException timerFailure)
    {
        await callback.Registered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var disposal = f.Resolver.DisposeAsync().AsTask();
        await callback.Entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        // The epoch request retains profile retirement, including this worker's actual cleanup.
        Assert.False(pending.IsCompleted);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        await f.Clock.DisposalEntered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        f.Clock.DisposalReleased.TrySetResult();
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Clock.ActiveTimers == 0).ConfigureAwait(true);
        Assert.False(disposal.IsCompleted); Assert.False(callback.Exited.Task.IsCompleted); Assert.Equal(1, f.Resolver.ActiveWorkers);
        callback.Release();
        var error = await Assert.ThrowsAnyAsync<Exception>(() => disposal.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        f.ExpectedDisposalFailure = error;
        Assert.True(Contains(error, timerFailure)); Assert.True(Contains(error, callback.Failure));
        Assert.Same(disposal, f.Resolver.DisposeAsync().AsTask());
        var repeated = await Record.ExceptionAsync(() => f.Resolver.DisposeAsync().AsTask()).ConfigureAwait(true);
        Assert.Same(error, repeated);
        var requestFailure = await Assert.ThrowsAnyAsync<Exception>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.True(Contains(requestFailure, timerFailure)); Assert.True(Contains(requestFailure, callback.Failure));
        Assert.True(callback.Exited.Task.IsCompletedSuccessfully);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Resolver.Statistics.SourceRequests);
        Assert.Equal(0, f.Resolver.Statistics.ActiveRequests); Assert.Equal(0, f.Clock.ActiveTimers);
    }

    private static bool Contains(Exception error, Exception expected)
        => ReferenceEquals(error, expected) || (error is AggregateException aggregate && aggregate.InnerExceptions.Any(item => Contains(item, expected)))
            || (error.InnerException is not null && Contains(error.InnerException, expected));

    private sealed class HeldCallback : IAsyncDisposable
    {
        private readonly ManualResetEventSlim released = new();
        private CancellationTokenRegistration registration;
        internal InvalidOperationException Failure { get; } = new("Controlled authenticated callback failure.");
        internal TaskCompletionSource Registered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Exited { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ValueTask<DnsUpstreamEvidence> ReadAsync(Task<DnsUpstreamEvidence> held, CancellationToken token)
        {
            registration = token.Register(() =>
            {
                Entered.TrySetResult();
                try
                {
                    if (!released.Wait(AnchorRefreshFixture.Timeout, CancellationToken.None)) throw new TimeoutException("Controlled callback was not released.");
                    throw Failure;
                }
                finally { Exited.TrySetResult(); }
            });
            Registered.TrySetResult(); return new(held);
        }
        internal void Release() => released.Set();
        public async ValueTask DisposeAsync()
        {
            released.Set();
            await registration.DisposeAsync().ConfigureAwait(true);
            released.Dispose();
        }
    }
}
