using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AdaptiveAnchorPollingCadenceTests
{
    [Fact]
    public async Task MissingTimingWaitsBootstrapThenUsesActualAcknowledgedTimingAtFiniteCap()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        var poller = f.CreateAdaptive(maximumAttempts: 2);
        Assert.Equal(TimeSpan.FromHours(2), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(0, f.Source.Upstream.Calls); f.Clock.Set(7200);
        Assert.Equal(TimeSpan.FromHours(1), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(1, poller.Statistics.Applied); f.Clock.Set(10_800);
        await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, poller.Statistics.Applied); Assert.Equal(2, f.Source.Store.Commits); Assert.Equal(0, f.Clock.ActiveTimers);
        f.Clock.Set(1_000_000); Assert.Equal(2, f.Source.Upstream.Calls);
    }

    [Fact]
    public async Task StartupUsesRemainingAcknowledgedIntervalInsteadOfBootstrap()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        SetProof(f, 20_000); await ApplyAsync(f).ConfigureAwait(true); f.Clock.Set(30);
        var poller = f.CreateAdaptive(maximumAttempts: 1);
        Assert.Equal(TimeSpan.FromSeconds(9970), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        f.Clock.Set(9999); Assert.Equal(1, f.Source.Upstream.Calls);
        f.Clock.Set(10_000); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, poller.Statistics.Attempts); Assert.Equal(3, f.Refresher.Current.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OverdueReceiptOrForwardWallJumpCannotSkipInitialMonotonicHour(bool wallOnly)
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        await ApplyAsync(f).ConfigureAwait(true); f.Clock.Set(4000, wallOnly);
        var poller = f.CreateAdaptive(maximumAttempts: 1);
        Assert.Equal(TimeSpan.FromHours(1), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        var start = wallOnly ? 0 : 4000;
        f.Clock.Set(start + 3599); Assert.Equal(1, f.Source.Upstream.Calls);
        f.Clock.Set(start + 3600); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, poller.Statistics.Attempts); Assert.Equal(2, f.Source.Upstream.Calls);
    }

    [Fact]
    public async Task AcquisitionTimeSpendsNextNormalWaitWithoutExtraCompletionHour()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Source.Upstream.Override = (_, _, _) =>
        {
            var reply = f.Source.Reply(); if (f.Source.Upstream.Calls == 1) f.Clock.Set(5400);
            return ValueTask.FromResult(reply);
        };
        var poller = f.CreateAdaptive(maximumAttempts: 2, refreshHours: 1);
        await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(3600);
        Assert.Equal(TimeSpan.FromSeconds(1800), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        f.Clock.Set(7199); Assert.Equal(1, f.Source.Upstream.Calls);
        f.Clock.Set(7200); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, poller.Statistics.Applied);
    }

    [Fact]
    public async Task RefusedRetryStartsAtLastAttemptRatherThanOldReceipt()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        SetProof(f, 100_000); await ApplyAsync(f).ConfigureAwait(true);
        f.Source.Upstream.Override = (_, _, _) => ValueTask.FromResult(f.Source.Reply(flags: 0x8432));
        var poller = f.CreateAdaptive(maximumAttempts: 2);
        Assert.Equal(TimeSpan.FromSeconds(50_000), await f.Clock.NextTimerAsync().ConfigureAwait(true)); f.Clock.Set(50_000);
        Assert.Equal(TimeSpan.FromSeconds(10_000), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(1, poller.Statistics.Refused); f.Clock.Set(60_000);
        await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, poller.Statistics.Refused); Assert.Equal(2, f.Refresher.Current.Revision); Assert.Equal(1, f.Source.Store.Commits);
    }

    [Fact]
    public async Task MissingTimingRefusalUsesBootstrapRetry()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Source.Upstream.Override = (_, _, _) => ValueTask.FromResult(f.Source.Reply(flags: 0x8432));
        var poller = f.CreateAdaptive(maximumAttempts: 2, refreshHours: 4, retryHours: 2);
        Assert.Equal(TimeSpan.FromHours(4), await f.Clock.NextTimerAsync().ConfigureAwait(true)); f.Clock.Set(14_400);
        Assert.Equal(TimeSpan.FromHours(2), await f.Clock.NextTimerAsync().ConfigureAwait(true)); f.Clock.Set(21_600);
        await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, poller.Statistics.Refused); Assert.Null(f.Refresher.CurrentTiming); Assert.Equal(0, f.Source.Store.Commits);
    }

    [Fact]
    public async Task ReceiptRevisionChangedDuringWaitIsRereadBeforeAttempt()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        await ApplyAsync(f).ConfigureAwait(true); var poller = f.CreateAdaptive(maximumAttempts: 1);
        Assert.Equal(TimeSpan.FromHours(1), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        f.Clock.Set(1800); SetProof(f, 20_000); await ApplyAsync(f).ConfigureAwait(true);
        f.Clock.Set(3600); Assert.Equal(TimeSpan.FromSeconds(8200), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(0, poller.Statistics.Attempts); Assert.Equal(2, f.Source.Upstream.Calls);
        f.Clock.Set(11_800); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, poller.Statistics.Applied); Assert.Equal(4, f.Refresher.Current.Revision);
    }

    [Fact]
    public async Task BackwardClockCannotRefillReceiptOrMoveAttemptEarlier()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        var poller = f.CreateAdaptive(maximumAttempts: 2); await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(7200);
        Assert.Equal(TimeSpan.FromHours(1), await f.Clock.NextTimerAsync().ConfigureAwait(true)); f.Clock.Set(0);
        Assert.Equal(1, poller.Statistics.Attempts); f.Clock.Set(10_799); Assert.Equal(1, f.Source.Upstream.Calls);
        f.Clock.Set(10_800); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, poller.Statistics.Applied); Assert.Equal(0, f.Clock.ActiveTimers);
    }

    [Fact]
    public async Task SeparateAcknowledgementEndsRetryEpisodeAndUsesItsCurrentNormalDeadline()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        SetProof(f, 100_000); await ApplyAsync(f).ConfigureAwait(true);
        f.Source.Upstream.Override = (_, _, _) => ValueTask.FromResult(f.Source.Reply(flags: 0x8432));
        var poller = f.CreateAdaptive(maximumAttempts: 2); await f.Clock.NextTimerAsync().ConfigureAwait(true); f.Clock.Set(50_000);
        Assert.Equal(TimeSpan.FromSeconds(10_000), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        f.Clock.Set(55_000); SetProof(f, 20_000); f.Source.Upstream.Override = null; await ApplyAsync(f).ConfigureAwait(true);
        f.Clock.Set(60_000); Assert.Equal(TimeSpan.FromSeconds(5000), await f.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(1, poller.Statistics.Attempts); Assert.Equal(3, f.Source.Upstream.Calls);
        f.Clock.Set(65_000); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, poller.Statistics.Applied); Assert.Equal(1, poller.Statistics.Refused); Assert.Equal(4, f.Refresher.Current.Revision);
    }

    internal static void SetProof(AnchorPollingFixture f, uint ttl)
    {
        f.Source.Records = [f.Source.Keys.Key(f.Source.Keys.A, ttl)];
        f.Source.Signatures = [f.Source.Keys.Sign(f.Source.Records, f.Source.Keys.A, expiration: 1_000_100)];
    }
    private static async Task ApplyAsync(AnchorPollingFixture f)
        => Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Refresher.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
}
