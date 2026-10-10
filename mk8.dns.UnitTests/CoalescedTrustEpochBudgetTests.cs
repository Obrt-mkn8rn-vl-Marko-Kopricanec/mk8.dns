using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CoalescedTrustEpochBudgetTests
{
    [Fact]
    public async Task CanceledIgnoringWorkerKeepsGlobalChargeAcrossSeveralCommittedRevisions()
    {
        var f = new CoalescedTrustEpochFixture(workers: 1, requests: 4, failureCache: true); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        f.Override = (_, _, _) => { entered.TrySetResult(); return new(held.Task); };
        using var caller = new CancellationTokenSource();
        var pending = f.Resolver.ResolveDnssecAsync(f.Question, caller.Token).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        await caller.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, f.Resolver.Statistics.ActiveRequests); Assert.Equal(1, f.Resolver.ActiveWorkers);
        for (var revision = 2; revision <= 4; revision++)
        {
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Data.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
            Assert.Equal(DnssecResolutionOutcome.Failure, (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
            Assert.Equal(revision, f.Resolver.Statistics.Revision);
            Assert.Single(f.Data.Calls); Assert.Equal(1, f.Resolver.ActiveWorkers);
            Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
        }
        var closing = f.Resolver.DisposeAsync().AsTask(); Assert.False(closing.IsCompleted);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        await closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Resolver.Statistics.OwnedProfiles);
        Assert.Equal(0, f.Clock.ActiveTimers); Assert.Equal(4, f.Data.Refresh.Current.Revision);
    }

    [Fact]
    public async Task FailedTimerCreationReturnsItsGlobalChargeWithoutSourceOrFailureHistory()
    {
        var f = new CoalescedTrustEpochFixture(workers: 1, failureCache: true); await using var lifetime = f.ConfigureAwait(true);
        f.Clock.FailCreation = true;
        await Assert.ThrowsAsync<IOException>(() => f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Resolver.Statistics.ActiveRequests);
        Assert.Empty(f.Data.Calls); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
        f.Clock.FailCreation = false;
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Clock.ActiveTimers);
    }

    [Fact]
    public async Task ActualCompletedProviderKeepsGlobalChargeDuringHeldTimerRetirement()
    {
        var f = new CoalescedTrustEpochFixture(workers: 1, requests: 4); await using var lifetime = f.ConfigureAwait(true);
        f.Clock.HoldDisposal = true;
        var pending = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await f.Clock.DisposalEntered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.False(pending.IsCompleted); Assert.Equal(1, f.Resolver.ActiveWorkers);
        Assert.Equal(0, f.Resolver.Statistics.SourceRequests);
        var other = new DnsQuestion(DnsName.Parse("other.example."), 1, 1);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await f.Resolver.ResolveDnssecAsync(other, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(2, f.Data.Calls.Count);
        f.Clock.DisposalReleased.TrySetResult();
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Clock.ActiveTimers);
    }
}
