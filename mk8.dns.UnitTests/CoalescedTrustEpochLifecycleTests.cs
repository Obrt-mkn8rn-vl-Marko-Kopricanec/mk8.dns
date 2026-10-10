using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CoalescedTrustEpochLifecycleTests
{
    [Fact]
    public async Task SharedDeadlineDoesNotRestartForLateWaiterOrReleaseIgnoringSource()
    {
        var f = new CoalescedTrustEpochFixture(workers: 1, failureCache: true); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        f.Override = (_, _, _) => { entered.TrySetResult(); return new(held.Task); };
        var first = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        f.Clock.Set(0.9);
        var second = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.CurrentWorkStatistics?.Waiters == 2).ConfigureAwait(true);
        f.Clock.Set(1);
        foreach (var pending in new[] { first, second })
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(1, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Resolver.Statistics.ActiveRequests);
        Assert.Equal(1, f.Resolver.Statistics.SourceRequests); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Single(f.Data.Calls); Assert.Equal(1, f.Clock.ActiveTimers);
        var drain = f.Resolver.DisposeAsync().AsTask(); Assert.False(drain.IsCompleted);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server)); await drain.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Clock.ActiveTimers);
    }

    [Fact]
    public async Task RevisionReplacementCannotJoinOrDeliverOldWorkEvenWithIdenticalPins()
    {
        var f = new CoalescedTrustEpochFixture(workers: 2); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys); var count = 0;
        f.Override = (question, server, _) =>
        {
            if (question.Type == 48 && Interlocked.Increment(ref count) == 1) { entered.TrySetResult(); return new(held.Task); }
            return ValueTask.FromResult(f.Default(question, server));
        };
        var old = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Data.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        f.Data.LastOctet = 2;
        var fresh = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome); Assert.Equal(2, Assert.Single(fresh.Answers).GetData()[3]);
        Assert.Equal(2, f.Resolver.Statistics.Revision); Assert.Equal(1, f.Resolver.Statistics.RetiredProfiles);
        Assert.False(old.IsCompleted); Assert.Equal(1, f.Resolver.ActiveWorkers); Assert.Equal(3, f.Data.Calls.Count);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => old.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Resolver.Statistics.RetiredProfiles);
        Assert.Equal(1, f.Resolver.Statistics.Entries);
    }

    [Fact]
    public async Task ClearBreaksJoiningAndOldStoreWithoutCancelingAdmittedSnapshot()
    {
        var f = new CoalescedTrustEpochFixture(workers: 2); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = f.Hold(f.Question); var originalReply = f.Default(f.Question, AnchorRefreshFixture.Server);
        var dataCalls = 0; CancellationToken originalToken = default;
        f.Override = (question, server, token) =>
        {
            if (question.Type != 48 && Interlocked.Increment(ref dataCalls) == 1)
            {
                originalToken = token; entered.TrySetResult(); return new(held.Task);
            }
            return ValueTask.FromResult(f.Default(question, server));
        };
        var original = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        f.Resolver.Clear(); Assert.False(originalToken.IsCancellationRequested); f.Data.LastOctet = 2;
        var newer = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, Assert.Single(newer.Answers).GetData()[3]);
        Assert.Equal(2, f.Resolver.CurrentWorkStatistics!.Started); Assert.Equal(0, f.Resolver.CurrentWorkStatistics.Coalesced);
        held.TrySetResult(originalReply);
        Assert.Equal(1, Assert.Single((await original.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Answers).GetData()[3]);
        var calls = f.Data.Calls.Count;
        Assert.Equal(2, Assert.Single((await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Answers).GetData()[3]);
        Assert.Equal(calls, f.Data.Calls.Count); Assert.Equal(1, f.Resolver.Statistics.Entries);
    }

    [Fact]
    public async Task ClosingJoinsActualWorkerAndRepeatCloseWithoutDisposingBorrowedRefresher()
    {
        var f = new CoalescedTrustEpochFixture(workers: 1); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        f.Override = (_, _, _) => { entered.TrySetResult(); return new(held.Task); };
        var pending = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var closing = f.Resolver.DisposeAsync().AsTask(); Assert.Same(closing, f.Resolver.DisposeAsync().AsTask());
        Assert.False(closing.IsCompleted); Assert.False(pending.IsCompleted); Assert.Equal(1, f.Resolver.ActiveWorkers);
        Assert.Throws<ObjectDisposedException>(f.Resolver.Clear);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        await closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Resolver.Statistics.OwnedProfiles);
        Assert.Equal(1, f.Data.Refresh.Current.Revision); Assert.Equal(0, f.Clock.ActiveTimers);
    }

    [Fact]
    public async Task PerCohortWaiterRefusalDoesNotCreateFailureHistoryOrExtraSourceWork()
    {
        var f = new CoalescedTrustEpochFixture(workers: 1, waiters: 1, failureCache: true); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        f.Override = (question, server, _) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        var pending = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Single(f.Data.Calls); Assert.Equal(1, f.Resolver.CurrentWorkStatistics!.AdmissionRejections);
        Assert.Equal(0, f.Resolver.Statistics.FailureEntries); held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProviderFaultIsNotOwnedAdmissionRefusalAndReleasesCharge(bool disposed)
    {
        var f = new CoalescedTrustEpochFixture(workers: 1, failureCache: true); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (_, _, _) => disposed ? throw new ObjectDisposedException(typeof(CoalescingDnssecResolver).FullName)
            : throw new InvalidOperationException("Controlled real provider fault.");
        var pending = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        if (disposed) await Assert.ThrowsAsync<ObjectDisposedException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        else await Assert.ThrowsAsync<InvalidOperationException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.ActiveWorkers == 0).ConfigureAwait(true);
        Assert.Equal(0, f.Resolver.Statistics.ActiveRequests); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
        Assert.Equal(0, f.Clock.ActiveTimers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NullNewBorrowedInputsRefuseBeforeTimersOrSource(bool clock)
    {
        var f = new CoalescedTrustEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        Assert.Throws<ArgumentNullException>(() => DnssecTrustEpochResolver.CreateWithCoalescing(f.Data.Refresh,
            f.Data.Anchors.Upstream, f.Data.Verifier, [AnchorRefreshFixture.Server], new DnssecTrustEpochPolicy(),
            clock ? new DnssecWorkPolicy() : null!, clock ? null! : f.Clock));
        Assert.Empty(f.Data.Calls); Assert.Equal(0, f.Clock.ActiveTimers); Assert.Equal(0, f.Resolver.ActiveWorkers);
    }
}
