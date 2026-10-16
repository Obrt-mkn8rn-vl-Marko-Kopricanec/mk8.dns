using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustEpochOwnershipTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HalfDrainedRetiredCohortRetainsBothRequestsUntilTheOtherRealProviderFinishes(bool fault)
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create(new DnssecTrustEpochPolicy(maximumActiveRequests: 2));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held1 = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var held2 = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstQuestion = f.Question; var secondQuestion = new DnsQuestion(DnsName.Parse("second.example."), 1, 1);
        var firstReply = f.Default(firstQuestion, AnchorRefreshFixture.Server); var secondReply = f.Default(secondQuestion, AnchorRefreshFixture.Server);
        var count = 0;
        f.Override = (question, server, _) =>
        {
            if (question.Type == 48) return ValueTask.FromResult(f.Default(question, server));
            if (Interlocked.Increment(ref count) == 2) entered.TrySetResult();
            return new(question.Equals(firstQuestion) ? held1.Task : held2.Task);
        };
        var pending1 = resolver.ResolveDnssecAsync(firstQuestion, CancellationToken.None).AsTask();
        var pending2 = resolver.ResolveDnssecAsync(secondQuestion, CancellationToken.None).AsTask();
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(firstQuestion, CancellationToken.None).ConfigureAwait(true)).Outcome);
            if (fault) held1.TrySetException(new ObjectDisposedException(typeof(CachingDnssecResolver).FullName));
            else held1.TrySetResult(firstReply);
            // Observe actual inner-source settlement without releasing the second provider.
            await WaitForSourceSettlementAsync(resolver).ConfigureAwait(true);
            AssertHeldRetirement(resolver, pending1, pending2);
            var closing = resolver.DisposeAsync().AsTask(); Assert.False(closing.IsCompleted);
        }, async () =>
        {
            held1.TrySetResult(firstReply); held2.TrySetResult(secondReply);
            await JoinRetiredCallsAsync(pending1.WaitAsync(CancellationToken.None), pending2.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        }).ConfigureAwait(true);
        if (fault) await Assert.ThrowsAsync<ObjectDisposedException>(() => pending1.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        else Assert.Equal(DnssecResolutionOutcome.Failure, (await pending1.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await pending2.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        await resolver.DisposeAsync().ConfigureAwait(true);
        Assert.Equal(0, resolver.Statistics.ActiveRequests); Assert.Equal(0, resolver.Statistics.OwnedProfiles);
    }

    private static Task JoinRetiredCallsAsync(Task first, Task second)
        => TestTaskSettlement.AllAsync(
            () => TestTaskSettlement.ObserveAsync(first.WaitAsync(CancellationToken.None), error => error is ObjectDisposedException),
            () => second.WaitAsync(CancellationToken.None));

    private static Task RetireOldCallAsync(Task pending, Task? closing, bool fail)
        => TestTaskSettlement.AllAsync(
            () => TestTaskSettlement.ObserveAsync(pending.WaitAsync(CancellationToken.None), error => fail && error is InvalidOperationException),
            async () => { if (closing is not null) await TestTaskSettlement.WaitAsync(closing.WaitAsync(CancellationToken.None), AnchorRefreshFixture.Timeout).ConfigureAwait(true); });

    private static async Task WaitForSourceSettlementAsync(DnssecTrustEpochResolver resolver)
    {
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        while (resolver.Statistics.SourceRequests != 1) await Task.Delay(1, deadline.Token).ConfigureAwait(true);
        Assert.Equal(2, resolver.Statistics.ActiveRequests);
    }

    private static void AssertHeldRetirement(DnssecTrustEpochResolver resolver, Task first, Task second)
    {
        Assert.False(first.IsCompleted); Assert.False(second.IsCompleted);
        Assert.Equal(2, resolver.Statistics.ActiveRequests); Assert.Equal(1, resolver.Statistics.RetiredProfiles);
        Assert.Equal(1, resolver.Statistics.SourceRequests);
    }

    [Fact]
    public async Task SharedQuotaBoundsSeveralRetiredEpochsUntilTheirActualProvidersFinish()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create(new DnssecTrustEpochPolicy(maximumActiveRequests: 2));
        var firstEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var second = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = f.Default(new(f.Anchors.Keys.Origin, 48, 1), AnchorRefreshFixture.Server);
        var count = 0;
        f.Override = (_, _, _) =>
        {
            if (Interlocked.Increment(ref count) == 1) { firstEntered.TrySetResult(); return new(first.Task); }
            secondEntered.TrySetResult(); return new(second.Task);
        };
        var pending1 = resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask(); Task<DnssecResolutionResult>? pending2 = null;
        await TestTaskSettlement.RunAsync(async () =>
        {
            await firstEntered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true);
            pending2 = resolver.ResolveDnssecAsync(new(DnsName.Parse("second.example."), 1, 1), CancellationToken.None).AsTask();
            await secondEntered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
            Assert.Equal(2, resolver.Statistics.ActiveRequests); Assert.Equal(2, resolver.Statistics.RetiredProfiles);
            Assert.Equal(3, resolver.Statistics.OwnedProfiles); Assert.Equal(2, f.Calls.Count);
        }, async () =>
        {
            first.TrySetResult(keys); second.TrySetResult(keys);
            await TestTaskSettlement.AllAsync(
                async () => await pending1.WaitAsync(CancellationToken.None).ConfigureAwait(true),
                async () => { if (pending2 is not null) await pending2.WaitAsync(CancellationToken.None).ConfigureAwait(true); }).ConfigureAwait(true);
        }).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await pending1.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await pending2!.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(0, resolver.Statistics.ActiveRequests); Assert.Equal(1, resolver.Statistics.OwnedProfiles);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LateValidOrFaultedOldProviderWorkRemainsOwnedAcrossRevisionChange(bool fail)
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create(new DnssecTrustEpochPolicy(maximumActiveRequests: 1));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var old = f.Default(f.Question, AnchorRefreshFixture.Server);
        f.Override = (question, server, _) =>
        {
            if (question.Type == 48) return ValueTask.FromResult(f.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        var pending = resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        Task? closing = null;
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true);
            var rejected = await resolver.ResolveDnssecAsync(new(DnsName.Parse("other.example."), 1, 1), CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Failure, rejected.Outcome);
            Assert.Equal(2, f.Calls.Count); Assert.Equal(1, resolver.Statistics.RetiredProfiles);
            Assert.Equal(1, resolver.Statistics.ActiveRequests); Assert.False(pending.IsCompleted);
            closing = resolver.DisposeAsync().AsTask();
            Assert.False(closing.IsCompleted); Assert.Same(closing, resolver.DisposeAsync().AsTask());
        }, async () =>
        {
            if (fail) held.TrySetException(new InvalidOperationException("Controlled actual old provider fault."));
            else held.TrySetResult(old);
            await RetireOldCallAsync(pending.WaitAsync(CancellationToken.None), closing?.WaitAsync(CancellationToken.None), fail).ConfigureAwait(true);
        }).ConfigureAwait(true);
        if (fail)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        }
        else
        {
            var result = await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers);
        }
        await closing!.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, resolver.Statistics.ActiveRequests); Assert.Equal(0, resolver.Statistics.OwnedProfiles);
        Assert.Equal(2, f.Refresh.Current.Revision); // Caller-owned source remains usable.
    }

    [Fact]
    public async Task AValidOldResultIsRefusedAfterCommitWithoutClosingTheNewEpoch()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var original = f.Default(f.Question, AnchorRefreshFixture.Server);
        f.Override = (question, server, _) =>
        {
            if (question.Type == 48) return ValueTask.FromResult(f.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        var pending = resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true);
        }, async () =>
        {
            held.TrySetResult(original);
            await pending.WaitAsync(CancellationToken.None).ConfigureAwait(true);
        }).ConfigureAwait(true);
        var stale = await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, stale.Outcome); Assert.Empty(stale.Answers);
        f.Override = null; f.LastOctet = 2;
        var fresh = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, Assert.Single(fresh.Answers).GetData()[3]); Assert.Equal(2, resolver.Statistics.Revision);
        Assert.Equal(0, resolver.Statistics.RetiredProfiles);
    }

    [Fact]
    public async Task CallerCancellationDoesNotRetireIgnoringProviderWorkOrCreateFailureHistory()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create(new DnssecTrustEpochPolicy(maximumActiveRequests: 1,
            failureCache: new DnssecFailureCachePolicy()));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Override = (_, _, _) => { entered.TrySetResult(); return new(held.Task); };
        using var caller = new CancellationTokenSource();
        var pending = resolver.ResolveDnssecAsync(f.Question, caller.Token).AsTask();
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, CancellationToken.None).ConfigureAwait(true);
            await caller.CancelAsync().ConfigureAwait(true);
            Assert.False(pending.IsCompleted); Assert.Equal(1, resolver.Statistics.ActiveRequests);
            Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
            Assert.Single(f.Calls); Assert.Equal(0, resolver.Statistics.FailureEntries);
        }, async () =>
        {
            held.TrySetResult(f.Default(new(f.Anchors.Keys.Origin, 48, 1), AnchorRefreshFixture.Server));
            await TestTaskSettlement.ObserveAsync(pending.WaitAsync(CancellationToken.None), error => error is OperationCanceledException).ConfigureAwait(true);
        }).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, resolver.Statistics.ActiveRequests); Assert.Equal(0, resolver.Statistics.FailureEntries);
    }

    [Fact]
    public async Task ProviderObjectDisposedFaultIsNotMistakenForOwnedCacheAdmissionRefusal()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        f.Override = (_, _, _) => throw new ObjectDisposedException("Controlled caller-owned provider.");
        await Assert.ThrowsAsync<ObjectDisposedException>(() => resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, resolver.Statistics.ActiveRequests);
    }
}
