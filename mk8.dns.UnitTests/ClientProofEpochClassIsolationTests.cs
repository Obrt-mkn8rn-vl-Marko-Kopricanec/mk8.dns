using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofEpochClassIsolationTests
{
    [Theory]
    [InlineData(1, 3)]
    [InlineData(2, 3)]
    [InlineData(1, 255)]
    [InlineData(2, 255)]
    public async Task OtherClassCannotSharePendingWorkOrCachedInAnswer(int workers, int recordClass)
    {
        var f = new ClientProofEpochFixture(coalesced: true, workers: workers);
        await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Anchors.Keys.Origin, 48, 1);
        var held = f.Hold(keys);
        f.Override = (question, server, _) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        var first = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var other = f.Question with { Class = (ushort)recordClass };
        var refused = await f.Resolver.ResolveDnssecAsync(other, CancellationToken.None).AsTask()
            .WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        AssertRefused(other, refused);
        Assert.False(first.IsCompleted);
        Assert.Single(f.Calls);
        var canonical = f.Question with { Name = DnsName.Parse("WWW.Example.") };
        var duplicate = f.Resolver.ResolveDnssecAsync(canonical, CancellationToken.None).AsTask();
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.CurrentWorkStatistics?.Coalesced == 1).ConfigureAwait(true);
        Assert.False(duplicate.IsCompleted);
        Assert.Equal(1, f.Resolver.ActiveWorkers);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        foreach (var pending in new[] { first, duplicate })
        {
            AssertAuthenticated(await pending.WaitAsync(AnchorRefreshFixture.Timeout,
                TimeProvider.System, CancellationToken.None).ConfigureAwait(true));
        }
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.ActiveWorkers == 0).ConfigureAwait(true);
        Assert.Equal(2, f.Calls.Count);
        Assert.Equal(0, f.Timers.ActiveTimers);
        Assert.Equal(1, f.Resolver.Statistics.Entries);
        AssertRefused(other, await f.Resolver.ResolveDnssecAsync(other, CancellationToken.None).ConfigureAwait(true));
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.ActiveWorkers == 0).ConfigureAwait(true);
        var hit = await f.Resolver.ResolveDnssecAsync(canonical, CancellationToken.None).ConfigureAwait(true);
        AssertAuthenticated(hit);
        Assert.Equal(canonical, hit.Question);
        Assert.Equal(2, f.Calls.Count);
        Assert.Equal(0, f.Resolver.Statistics.ActiveRequests);
        Assert.Equal(1, f.Resolver.Statistics.Entries);
    }

    private static void AssertAuthenticated(DnssecResolutionResult result)
    {
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.NotNull(result.ClientProof);
        Assert.NotEmpty(result.Answers);
        Assert.True(result.AuthenticatedTtl > 0);
    }

    private static void AssertRefused(DnsQuestion question, DnssecResolutionResult result)
    {
        Assert.Equal(question, result.Question);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Equal(2, result.ResponseCode);
        Assert.Equal(0u, result.AuthenticatedTtl);
        Assert.Null(result.ClientProof);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
    }
}
