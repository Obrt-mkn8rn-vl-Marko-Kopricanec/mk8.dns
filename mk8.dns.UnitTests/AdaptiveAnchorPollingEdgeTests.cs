using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AdaptiveAnchorPollingEdgeTests
{
    [Fact]
    public async Task WorkLongerThanIntervalAllowsOneNextAttemptWithoutCatchupBurst()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        AdaptiveAnchorPollingCadenceTests.SetProof(f, 20_000);
        f.Source.Upstream.Override = (_, _, _) =>
        {
            var reply = f.Source.Reply(); if (f.Source.Upstream.Calls == 1) f.Clock.Set(18_000);
            return ValueTask.FromResult(reply);
        };
        var poller = f.CreateAdaptive(refreshHours: 1);
        await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(3600);
        Assert.Equal(TimeSpan.FromSeconds(10_000), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(2, poller.Statistics.Attempts); Assert.Equal(2, f.Source.Upstream.Calls);
        f.Clock.Set(27_999); Assert.Equal(2, f.Source.Upstream.Calls);
        f.Clock.Set(28_000); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(3, poller.Statistics.Applied); Assert.Equal(0, f.Clock.ActiveTimers);
    }

    [Fact]
    public async Task BusyUsesRetryAndStoppingDoesNotJoinExternalSourceWork()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Source.Upstream.Override = (_, _, _) => { entered.TrySetResult(); return new(held.Task); };
        var external = f.Refresher.RefreshAsync(CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var poller = f.CreateAdaptive(); await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(7200);
            Assert.Equal(TimeSpan.FromHours(1), await f.Clock.NextTimerAsync().ConfigureAwait(true));
            Assert.Equal(1, poller.Statistics.Busy); Assert.Equal(1, f.Source.Upstream.Calls);
            await poller.DisposeAsync().AsTask().WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.False(external.IsCompleted); Assert.Equal(0, f.Clock.ActiveTimers);
        }
        finally { held.TrySetResult(f.Source.Reply()); await external.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
    }

    [Fact]
    public async Task ClosedBorrowedSourceFaultsAfterTimerRetirementWithoutQuery()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        var poller = f.CreateAdaptive(); f.ExpectFault(poller);
        await f.Clock.NextTimerAsync().ConfigureAwait(true); await f.Refresher.DisposeAsync().ConfigureAwait(true); f.Clock.Set(7200);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, f.Source.Upstream.Calls); Assert.Equal(0, f.Clock.ActiveTimers);
    }

    [Fact]
    public async Task EarlyTimerBudgetStillFailsBeforeAnyAdaptiveQuery()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Clock.FireEarly = true; var poller = f.CreateAdaptive(); f.ExpectFault(poller);
        await Assert.ThrowsAsync<IOException>(() => poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, f.Source.Upstream.Calls); Assert.Equal(0, f.Clock.ActiveTimers); Assert.True(poller.Statistics.Completed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task NullBorrowedInputRefusesBeforeTimerOrSource(int missing)
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        var policy = new DnssecAnchorPollingPolicy(TimeSpan.FromHours(2), TimeSpan.FromHours(1));
        Assert.Throws<ArgumentNullException>(() => DnssecAnchorPoller.CreateWithAuthenticatedTiming(missing == 0 ? null! : f.Refresher,
            missing == 1 ? null! : policy, missing == 2 ? null! : f.Clock));
        Assert.Equal(0, f.Source.Upstream.Calls); Assert.Equal(0, f.Clock.ActiveTimers);
    }
}
