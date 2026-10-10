using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorPollingAdmissionTests
{
    [Theory]
    [InlineData(0.99, 1, 16)]
    [InlineData(361, 1, 16)]
    [InlineData(2, 0.99, 16)]
    [InlineData(48, 25, 16)]
    [InlineData(1, 2, 16)]
    [InlineData(2, 1, 0)]
    [InlineData(2, 1, 257)]
    public void InvalidExplicitPolicyRefusesBeforeAnySessionWork(double refreshHours, double retryHours, int attempts)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecAnchorPollingPolicy(TimeSpan.FromHours(refreshHours), TimeSpan.FromHours(retryHours), attempts));

    [Theory]
    [InlineData(1, 1, 1)]
    [InlineData(360, 24, 256)]
    public void PolicyOwnsBoundedIntervalsAndAttemptCap(double refreshHours, double retryHours, int attempts)
    {
        var policy = new DnssecAnchorPollingPolicy(TimeSpan.FromHours(refreshHours), TimeSpan.FromHours(retryHours), attempts);
        Assert.Equal(TimeSpan.FromHours(refreshHours), policy.RefreshInterval);
        Assert.Equal(TimeSpan.FromHours(retryHours), policy.RetryInterval); Assert.Equal(attempts, policy.MaximumAttempts);
    }

    [Fact]
    public async Task NullOrClosedBorrowedSourceDoesNotAcquireTimersOrQuery()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var policy = new DnssecAnchorPollingPolicy(TimeSpan.FromHours(2), TimeSpan.FromHours(1));
        Assert.Throws<ArgumentNullException>(() => new DnssecAnchorPoller(null!, policy, fixture.Clock));
        Assert.Throws<ArgumentNullException>(() => new DnssecAnchorPoller(fixture.Refresher, null!, fixture.Clock));
        Assert.Throws<ArgumentNullException>(() => new DnssecAnchorPoller(fixture.Refresher, policy, null!));
        await fixture.Refresher.DisposeAsync().ConfigureAwait(true);
        Assert.Throws<ObjectDisposedException>(() => new DnssecAnchorPoller(fixture.Refresher, policy, fixture.Clock));
        Assert.Equal(0, fixture.Clock.ActiveTimers); Assert.Equal(0, fixture.Source.Upstream.Calls);
    }

    [Fact]
    public async Task ClosingWaitingSessionSharesRealCompletionAndPreservesBorrowedSource()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var poller = fixture.Create();
        Assert.Equal(TimeSpan.FromHours(2), await fixture.Clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(0, fixture.Source.Upstream.Calls);
        var close = poller.DisposeAsync().AsTask(); Assert.Same(close, poller.DisposeAsync().AsTask());
        await close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.True(poller.Statistics.Completed); Assert.True(poller.Statistics.Closing); Assert.False(poller.Statistics.Waiting);
        Assert.Equal(0, fixture.Clock.ActiveTimers); Assert.Equal(0, poller.Statistics.Attempts);
        Assert.Equal(1, fixture.Refresher.Current.Revision);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await fixture.Refresher.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
    }
}
