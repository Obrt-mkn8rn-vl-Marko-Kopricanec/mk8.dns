using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofEpochRetirementTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RevisionRetirementRetainsProviderAndCallbackCharge(bool callbackFirst)
    {
        var f = new ClientProofEpochFixture(coalesced: true, workers: 1); await using var lifetime = f.ConfigureAwait(true);
        using var release = new ManualResetEventSlim();
        var registered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        CancellationTokenRegistration registration = default;
        f.Override = (_, _, token) =>
        {
            registration = token.Register(() =>
            {
                entered.TrySetResult();
                try
                {
                    if (!release.Wait(AnchorRefreshFixture.Timeout, CancellationToken.None)) throw new TimeoutException("Retired callback not released.");
                }
                finally { exited.TrySetResult(); }
            });
            registered.TrySetResult(); return new(held.Task);
        };
        var pending = f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask();
        try
        {
            await registered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
            Assert.Equal(DnssecResolutionOutcome.Failure,
                (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
            Assert.Equal(2, f.Resolver.Statistics.Revision);
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, f.Resolver.ActiveWorkers); Assert.False(pending.IsCompleted);
            await AssertHalfDrainAsync(f, callbackFirst, release, exited, held, keys, pending).ConfigureAwait(true);
        }
        finally
        {
            release.Set(); held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
            try { await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
            catch (OperationCanceledException) { }
            await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.ActiveWorkers == 0).ConfigureAwait(true);
            await registration.DisposeAsync().ConfigureAwait(true);
        }
        Assert.True(pending.IsCanceled);
        f.Override = null;
        Assert.NotNull((await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).ClientProof);
        Assert.Equal(0, f.Resolver.Statistics.RetiredProfiles); Assert.Equal(0, f.Timers.ActiveTimers);
    }
    private static async Task AssertHalfDrainAsync(ClientProofEpochFixture f, bool callbackFirst,
        ManualResetEventSlim release, TaskCompletionSource exited, TaskCompletionSource<DnsUpstreamEvidence> held,
        DnsQuestion keys, Task<DnssecResolutionResult> pending)
    {
        if (callbackFirst)
        {
            release.Set(); await exited.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, f.Resolver.Statistics.SourceRequests);
        }
        else
        {
            held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
            await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Timers.ActiveTimers == 0).ConfigureAwait(true);
            Assert.False(exited.Task.IsCompleted);
        }
        Assert.Equal(1, f.Resolver.ActiveWorkers); Assert.False(pending.IsCompleted);
        var refused = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, refused.Outcome); Assert.Null(refused.ClientProof);
        Assert.Single(f.Calls); Assert.Equal(0, f.Resolver.Statistics.Entries);
    }

}
