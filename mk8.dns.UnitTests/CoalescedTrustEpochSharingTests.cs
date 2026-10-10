using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CoalescedTrustEpochSharingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CanonicalSameQuestionSharesOneActualKeyAndDataResolution(bool alternateCase)
    {
        var f = new CoalescedTrustEpochFixture(workers: 1); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        f.Override = (question, server, _) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        var first = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var question = alternateCase ? new DnsQuestion(DnsName.Parse("WWW.Example."), 1, 1) : f.Question;
        var second = f.Resolver.ResolveDnssecAsync(question, CancellationToken.None).AsTask();
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.CurrentWorkStatistics?.Coalesced == 1).ConfigureAwait(true);
        Assert.Equal(1, f.Resolver.ActiveWorkers); Assert.Equal(2, f.Resolver.Statistics.ActiveRequests);
        Assert.Single(f.Data.Calls); held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        foreach (var pending in new[] { first, second })
            Assert.Equal(DnssecResolutionOutcome.Authenticated, (await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(2, f.Data.Calls.Count); Assert.Equal(1, f.Resolver.Statistics.Entries);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Clock.ActiveTimers);
        var calls = f.Data.Calls.Count;
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(calls, f.Data.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DistinctNameOrTypeCannotJoinAnotherQuestion(bool otherType)
    {
        var f = new CoalescedTrustEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        var keyCalls = 0;
        f.Override = (question, server, _) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Default(question, server));
            if (Interlocked.Increment(ref keyCalls) == 2) entered.TrySetResult();
            return new(held.Task);
        };
        var first = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        var other = otherType ? new DnsQuestion(f.Question.Name, 28, 1) : new DnsQuestion(DnsName.Parse("other.example."), 1, 1);
        var second = f.Resolver.ResolveDnssecAsync(other, CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Resolver.CurrentWorkStatistics!.Coalesced);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        foreach (var pending in new[] { first, second })
            Assert.Equal(DnssecResolutionOutcome.Authenticated, (await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(4, f.Data.Calls.Count); Assert.Equal(0, f.Resolver.ActiveWorkers);
    }

    [Fact]
    public async Task CancelingOneWaiterDoesNotCancelTheOtherOrReleaseActualWorker()
    {
        var f = new CoalescedTrustEpochFixture(workers: 1); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        CancellationToken actual = default;
        f.Override = (question, server, token) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Default(question, server));
            actual = token; entered.TrySetResult(); return new(held.Task);
        };
        using var caller = new CancellationTokenSource();
        var first = f.Resolver.ResolveDnssecAsync(f.Question, caller.Token).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var second = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.CurrentWorkStatistics?.Waiters == 2).ConfigureAwait(true);
        await caller.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.False(actual.IsCancellationRequested); Assert.False(second.IsCompleted);
        Assert.Equal(1, f.Resolver.ActiveWorkers); Assert.Equal(1, f.Resolver.Statistics.ActiveRequests);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await second.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(0, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Clock.ActiveTimers);
    }
}
