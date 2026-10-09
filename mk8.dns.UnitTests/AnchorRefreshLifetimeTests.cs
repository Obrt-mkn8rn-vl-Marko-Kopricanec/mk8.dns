using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRefreshLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AcquisitionTimeSpendsReceivedTtlOnMonotonicOrForwardWallClock(bool wallOnly)
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        f.Upstream.Override = (_, _, _) =>
        {
            var reply = f.Reply();
            if (wallOnly) f.Keys.Clock.SetWall(3700); else f.Keys.Clock.Advance(3600);
            return ValueTask.FromResult(reply);
        };
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(0, f.Store.Commits); Assert.Equal(1, session.Current.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PostVerifierFreshnessAndSignatureWindowsRefuseDelayedProof(bool expireWindow)
    {
        using var f = new AnchorRefreshFixture();
        var verifier = new DnssecChainFixture.CountingVerifier { AfterVerify = () => f.Keys.Clock.Advance(expireWindow ? 86400 : 3600) };
        await using var session = f.Create(verifier);
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(1, verifier.Calls); Assert.Equal(0, f.Store.Commits);
    }

    [Fact]
    public async Task ClockRollbackCannotReviveCapturedExpiredReplyOrAdvanceHoldWithOnlyOneClock()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        f.Keys.Clock.SetMonotonic(TimeSpan.FromDays(31).TotalSeconds);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Single(session.Current.Anchors);
        f.Keys.Clock.SetMonotonic(0);
        f.Keys.Clock.SetWall(100 + (long)TimeSpan.FromDays(31).TotalSeconds);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        // Both high-water clocks have now spent the hold, despite a later rollback.
        Assert.Equal(2, session.Current.Anchors.Count);
        // The accepted serial window includes its expiration second.
        var captured = f.Reply(); f.Keys.Clock.Advance(86401);
        f.Upstream.Override = (_, _, _) => ValueTask.FromResult(captured);
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        f.Keys.Clock.SetWall(100); f.Keys.Clock.SetMonotonic(0);
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
    }
}
