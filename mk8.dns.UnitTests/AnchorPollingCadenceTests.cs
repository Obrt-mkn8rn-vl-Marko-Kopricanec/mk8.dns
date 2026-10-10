using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorPollingCadenceTests
{
    [Fact]
    public async Task StartupWaitsAndSuccessfulRefreshesStopAtFiniteAttemptCap()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var poller = fixture.Create(maximumAttempts: 2);
        Assert.Equal(TimeSpan.FromHours(2), await fixture.Clock.NextTimerAsync().ConfigureAwait(true));
        fixture.Clock.Set(7199); Assert.Equal(0, fixture.Source.Upstream.Calls);
        fixture.Clock.Set(7200);
        Assert.Equal(TimeSpan.FromHours(2), await fixture.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(1, fixture.Source.Store.Commits); Assert.Equal(2, fixture.Refresher.Current.Revision);
        fixture.Clock.Set(14_400); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, poller.Statistics.Attempts); Assert.Equal(2, poller.Statistics.Applied);
        Assert.Equal(2, fixture.Source.Upstream.Calls); Assert.Equal(3, fixture.Refresher.Current.Revision);
        Assert.True(poller.Statistics.Completed); Assert.Equal(0, fixture.Clock.ActiveTimers);
        fixture.Clock.Set(1_000_000); Assert.Equal(2, fixture.Source.Upstream.Calls);
    }

    [Fact]
    public async Task RefusedAcquisitionUsesExplicitRetryThenSuccessfulCadenceWithoutBootstrapFallback()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        fixture.Source.Upstream.Override = (_, _, _) => ValueTask.FromResult(fixture.Source.Upstream.Calls == 1 ? fixture.Source.Reply(flags: 0x8432) : fixture.Source.Reply());
        var poller = fixture.Create(); await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        Assert.Equal(TimeSpan.FromHours(1), await fixture.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(1, poller.Statistics.Refused); Assert.Equal(0, fixture.Source.Store.Commits); Assert.Equal(1, fixture.Refresher.Current.Revision);
        fixture.Clock.Set(10_800); Assert.Equal(TimeSpan.FromHours(2), await fixture.Clock.NextTimerAsync().ConfigureAwait(true));
        fixture.Clock.Set(18_000); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(3, poller.Statistics.Attempts); Assert.Equal(2, poller.Statistics.Applied); Assert.Equal(1, poller.Statistics.Refused);
        Assert.Equal(3, fixture.Source.Upstream.Calls); Assert.Equal(2, fixture.Source.Store.Commits);
    }

    [Fact]
    public async Task ContainedAcquisitionIoFailureUsesRetryAndKeepsBorrowedSourceHealthy()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        fixture.Source.Upstream.Override = (_, _, _) => fixture.Source.Upstream.Calls == 1
            ? throw new IOException("Controlled acquisition refusal.") : ValueTask.FromResult(fixture.Source.Reply());
        var poller = fixture.Create(maximumAttempts: 2); await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        Assert.Equal(TimeSpan.FromHours(1), await fixture.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(1, poller.Statistics.Refused); Assert.Equal(1, fixture.Refresher.Current.Revision);
        fixture.Clock.Set(10_800); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, poller.Statistics.Applied); Assert.Equal(2, fixture.Source.Upstream.Calls); Assert.Equal(1, fixture.Source.Store.Commits);
    }

    [Fact]
    public async Task WallJumpCannotTriggerPollingAndMissedIntervalsDoNotCreateCatchupBurst()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var poller = fixture.Create(); await fixture.Clock.NextTimerAsync().ConfigureAwait(true);
        fixture.Clock.Set(90_000, wallOnly: true); Assert.Equal(0, fixture.Source.Upstream.Calls);
        fixture.Clock.Set(90_000); Assert.Equal(TimeSpan.FromHours(2), await fixture.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(1, fixture.Source.Upstream.Calls); Assert.Equal(1, poller.Statistics.Attempts);
        fixture.Clock.Set(97_199); Assert.Equal(1, fixture.Source.Upstream.Calls);
        fixture.Clock.Set(97_200); await fixture.Clock.NextTimerAsync().ConfigureAwait(true); Assert.Equal(2, fixture.Source.Upstream.Calls);
    }

    [Fact]
    public async Task BackwardClockCannotRepeatCompletedPollOrMoveNextCadenceEarlier()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var poller = fixture.Create(maximumAttempts: 2); await fixture.Clock.NextTimerAsync().ConfigureAwait(true);
        fixture.Clock.Set(7200); await fixture.Clock.NextTimerAsync().ConfigureAwait(true);
        fixture.Clock.Set(0); Assert.Equal(1, poller.Statistics.Attempts); Assert.Equal(1, fixture.Source.Store.Commits);
        fixture.Clock.Set(14_399); Assert.Equal(1, fixture.Source.Upstream.Calls);
        fixture.Clock.Set(14_400); await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, poller.Statistics.Applied); Assert.Equal(2, fixture.Source.Store.Commits); Assert.Equal(0, fixture.Clock.ActiveTimers);
    }

    [Fact]
    public async Task SynchronouslyEarlyTimersCannotAcquireAndTheirSignalBudgetIsFinite()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        fixture.Clock.FireEarly = true; var poller = fixture.Create(); fixture.ExpectFault(poller);
        await Assert.ThrowsAsync<IOException>(() => poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, fixture.Source.Upstream.Calls); Assert.Equal(0, fixture.Source.Store.Commits);
        Assert.Equal(0, fixture.Clock.ActiveTimers); Assert.True(poller.Statistics.Completed);
    }
}
