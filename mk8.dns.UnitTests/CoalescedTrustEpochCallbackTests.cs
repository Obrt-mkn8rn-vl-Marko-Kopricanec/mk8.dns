using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CoalescedTrustEpochCallbackTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualCallbackAndProviderHalvesKeepGlobalChargeUntilBothSettle(bool callbackFirst)
    {
        var f = new CoalescedTrustEpochFixture(workers: 1); await using var lifetime = f.ConfigureAwait(true);
        using var release = new ManualResetEventSlim();
        var registered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Data.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        CancellationTokenRegistration registration = default;
        f.Override = (_, _, token) =>
        {
            registration = token.Register(() =>
            {
                entered.TrySetResult();
                try
                {
                    if (!release.Wait(AnchorRefreshFixture.Timeout, CancellationToken.None)) throw new TimeoutException("Controlled epoch callback not released.");
                }
                finally { exited.TrySetResult(); }
            });
            registered.TrySetResult(); return new(held.Task);
        };
        using var caller = new CancellationTokenSource();
        var pending = f.Resolver.ResolveDnssecAsync(f.Question, caller.Token).AsTask();
        try
        {
            await registered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await caller.CancelAsync().ConfigureAwait(true);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, f.Resolver.ActiveWorkers); Assert.Equal(0, f.Resolver.Statistics.ActiveRequests);
            await AssertHalfDrainAsync(f, callbackFirst, release, exited, held, keys).ConfigureAwait(true);
        }
        finally
        {
            release.Set(); held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
            await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.ActiveWorkers == 0).ConfigureAwait(true);
            await registration.DisposeAsync().ConfigureAwait(true);
        }
        Assert.Equal(0, f.Clock.ActiveTimers); Assert.Equal(0, f.Resolver.Statistics.SourceRequests);
    }
    private static async Task AssertHalfDrainAsync(CoalescedTrustEpochFixture f, bool callbackFirst,
        ManualResetEventSlim release, TaskCompletionSource exited, TaskCompletionSource<DnsUpstreamEvidence> held, DnsQuestion keys)
    {
        if (callbackFirst)
        {
            release.Set(); await exited.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, f.Resolver.Statistics.SourceRequests); Assert.Equal(1, f.Clock.ActiveTimers);
        }
        else
        {
            held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
            await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Clock.ActiveTimers == 0).ConfigureAwait(true);
            Assert.False(exited.Task.IsCompleted); Assert.Equal(0, f.Resolver.Statistics.SourceRequests);
        }
        Assert.Equal(1, f.Resolver.ActiveWorkers);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Single(f.Data.Calls); Assert.Equal(0, f.Resolver.Statistics.Entries);
    }

}
