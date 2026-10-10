using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AdaptiveAnchorPollingExhaustionTests
{
    [Fact]
    public async Task RepeatedAcknowledgementsExhaustReceiptRechecksWithoutPollerQuery()
    {
        var f = new AnchorPollingFixture(); await using var lifetime = f.ConfigureAwait(true);
        AdaptiveAnchorPollingCadenceTests.SetProof(f, 20_000);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Refresher.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        var poller = f.CreateAdaptive(maximumAttempts: 1); f.ExpectFault(poller);
        double now = 0;
        for (var recheck = 0; recheck < 128; recheck++)
        {
            var delay = await f.Clock.NextTimerAsync().ConfigureAwait(true);
            Assert.True(delay > TimeSpan.Zero);
            f.Clock.Set(now + (delay.TotalSeconds / 2));
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Refresher.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
            now += delay.TotalSeconds; f.Clock.Set(now);
            Assert.Equal(0, poller.Statistics.Attempts);
        }
        await Assert.ThrowsAsync<IOException>(() => poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(129, f.Source.Upstream.Calls); Assert.Equal(129, f.Source.Store.Commits);
        Assert.Equal(0, poller.Statistics.Attempts); Assert.True(poller.Statistics.Completed);
        Assert.Equal(0, f.Clock.ActiveTimers);
    }
}
