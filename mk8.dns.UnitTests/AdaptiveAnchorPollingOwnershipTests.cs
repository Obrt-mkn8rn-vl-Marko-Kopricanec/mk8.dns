using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AdaptiveAnchorPollingOwnershipTests
{
    [Fact]
    public async Task StopDuringTimerRetirementJoinsTimerAndNeverStartsSource()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Clock.HoldDisposal = true; var poller = f.CreateAdaptive(); await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(7200);
        await f.Clock.DisposalEntered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var close = poller.DisposeAsync().AsTask(); Assert.Same(close, poller.DisposeAsync().AsTask());
        Assert.False(close.IsCompleted); Assert.Equal(1, f.Clock.ActiveTimers); Assert.Equal(0, f.Source.Upstream.Calls);
        f.Clock.DisposalReleased.TrySetResult(); await close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, f.Clock.ActiveTimers); Assert.True(poller.Statistics.Completed); Assert.Equal(1, f.Refresher.Current.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StopOwnsActualProviderAndBlockedCallbackUntilBothSettle(bool providerFirst)
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var callback = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationTokenRegistration registration = default;
        f.Source.Upstream.Override = (_, _, token) =>
        {
            registration = token.Register(() => { callback.TrySetResult(); if (!release.Wait(AnchorPollingFixture.Timeout, CancellationToken.None)) throw new TimeoutException(); });
            entered.TrySetResult(); return new(held.Task);
        };
        var poller = f.CreateAdaptive(); await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(7200);
        try
        {
            await entered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var close = poller.DisposeAsync().AsTask(); await callback.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            if (providerFirst) { held.TrySetResult(f.Source.Reply()); } else { release.Set(); await registration.DisposeAsync().ConfigureAwait(true); }
            Assert.False(close.IsCompleted); Assert.Equal(0, f.Source.Store.Commits);
            release.Set(); held.TrySetResult(f.Source.Reply()); await close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.True(poller.Statistics.Completed); Assert.Equal(1, poller.Statistics.Attempts); Assert.Equal(0, f.Clock.ActiveTimers);
        }
        finally { release.Set(); held.TrySetResult(f.Source.Reply()); await registration.DisposeAsync().ConfigureAwait(true); }
    }

    [Fact]
    public async Task MissingAcknowledgementFaultsAdaptiveCompletionAndNeverRetries()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Source.Store.ReplyRevision = 7; var poller = f.CreateAdaptive(); f.ExpectFault(poller);
        await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(7200);
        await Assert.ThrowsAsync<InvalidDataException>(() => poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(1, poller.Statistics.Attempts); Assert.Equal(0, poller.Statistics.Applied); Assert.Equal(0, f.Clock.ActiveTimers);
        Assert.Throws<IOException>(() => f.Refresher.CurrentTiming); f.Clock.Set(100_000); Assert.Equal(1, f.Source.Upstream.Calls);
    }

    [Fact]
    public async Task SuccessfulAcknowledgementWinsConcurrentStopAndStillPublishesTiming()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        var poller = f.CreateAdaptive();
        Task? close = null;
        f.Source.Store.AfterCommit = () => close = poller.DisposeAsync().AsTask();
        await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(7200);
        await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(close); await close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, poller.Statistics.Applied); Assert.Equal(1, poller.Statistics.Attempts);
        Assert.Equal(2, f.Refresher.Current.Revision); Assert.Equal(2, Assert.IsType<Mk8.Dns.Engine.Recursive.DnssecAnchorRefreshTiming>(f.Refresher.CurrentTiming).Revision);
        Assert.Equal(0, f.Clock.ActiveTimers); Assert.True(poller.Statistics.Completed);
    }
}
