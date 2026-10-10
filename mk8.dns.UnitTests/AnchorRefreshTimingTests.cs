using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRefreshTimingTests
{
    [Fact]
    public async Task RecoveryHasNoInventedTimingAndOnlyAcknowledgedFreshRevisionPublishesIt()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        Assert.Null(session.CurrentTiming);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        var timing = Assert.IsType<DnssecAnchorRefreshTiming>(session.CurrentTiming);
        Assert.Equal(2, timing.Revision); Assert.Equal(f.Keys.Origin, timing.Origin); Assert.Equal(3600u, timing.Proof.OriginalTtl);
        Assert.Equal(TimeSpan.FromHours(1), timing.RemainingQueryInterval); Assert.Equal(TimeSpan.Zero, timing.ChargedElapsed);
        await using var restarted = f.Create(); Assert.Equal(2, restarted.Current.Revision); Assert.Null(restarted.CurrentTiming);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OriginalAcquisitionVerifierAndCommitTimeIsChargedOnBothHighWaterClockPaths(bool wallOnly)
    {
        using var f = new AnchorRefreshFixture(); var elapsed = 0;
        void Spend(int seconds)
        {
            elapsed += seconds;
            if (wallOnly) f.Keys.Clock.SetWall(100 + elapsed); else f.Keys.Clock.SetMonotonic(elapsed);
        }
        f.Upstream.Override = (_, _, _) => { var reply = f.Reply(); Spend(30); return ValueTask.FromResult(reply); };
        var verifier = new DnssecChainFixture.CountingVerifier { AfterVerify = () => Spend(20) }; f.Store.AfterCommit = () => Spend(10);
        await using var session = f.Create(verifier);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        var timing = Assert.IsType<DnssecAnchorRefreshTiming>(session.CurrentTiming);
        Assert.Equal(TimeSpan.FromSeconds(60), timing.ChargedElapsed); Assert.Equal(TimeSpan.FromSeconds(3540), timing.RemainingQueryInterval);
        Assert.Equal(TimeSpan.FromSeconds(3540), timing.RemainingRetryInterval); Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(100), timing.ReceivedUtc);
        f.Keys.Clock.SetWall(100); f.Keys.Clock.SetMonotonic(0);
        var rollback = Assert.IsType<DnssecAnchorRefreshTiming>(session.CurrentTiming);
        Assert.Equal(timing.ChargedElapsed, rollback.ChargedElapsed); Assert.Equal(timing.RemainingQueryInterval, rollback.RemainingQueryInterval);
    }

    [Fact]
    public async Task RefusedAcquisitionKeepsFirstAcknowledgedTimingAndContinuesSpendingIt()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        f.Keys.Clock.Advance(120); f.Upstream.Override = (_, _, _) => ValueTask.FromResult(f.Reply(flags: 0x8432));
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        var timing = Assert.IsType<DnssecAnchorRefreshTiming>(session.CurrentTiming);
        Assert.Equal(2, timing.Revision); Assert.Equal(TimeSpan.FromSeconds(3480), timing.RemainingQueryInterval);
        f.Keys.Clock.Advance(4000); var overdue = Assert.IsType<DnssecAnchorRefreshTiming>(session.CurrentTiming);
        Assert.Equal(TimeSpan.Zero, overdue.RemainingQueryInterval); Assert.Equal(TimeSpan.Zero, overdue.RemainingRetryInterval);
        Assert.Equal(1, f.Store.Commits); Assert.Equal(2, session.Current.Revision);
    }

    [Fact]
    public async Task TimingAndRevisionStayOldUntilActualAcknowledgementThenAdvanceTogether()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Store.AfterCommit = () => { entered.TrySetResult(); if (!release.Wait(AnchorRefreshFixture.Timeout, CancellationToken.None)) throw new TimeoutException(); };
        f.Records = [f.Keys.Key(f.Keys.A, 20_000)]; f.Signatures = [f.Keys.Sign(f.Records, f.Keys.A, expiration: 100_100)];
        var next = session.RefreshAsync(CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(3, f.Store.State.Revision); Assert.Equal(2, session.Current.Revision);
            Assert.Equal(2, Assert.IsType<DnssecAnchorRefreshTiming>(session.CurrentTiming).Revision);
            f.Keys.Clock.SetMonotonic(60); release.Set();
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await next.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true));
            var timing = Assert.IsType<DnssecAnchorRefreshTiming>(session.CurrentTiming);
            Assert.Equal(3, timing.Revision); Assert.Equal(20_000u, timing.Proof.OriginalTtl);
            Assert.Equal(TimeSpan.FromSeconds(60), timing.ChargedElapsed); Assert.Equal(TimeSpan.FromSeconds(9940), timing.RemainingQueryInterval);
        }
        finally { release.Set(); await next.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
    }

    [Fact]
    public async Task LostAcknowledgementHidesTimingAndFaultsCurrentSource()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create(); f.Store.ReplyRevision = 7;
        await Assert.ThrowsAsync<InvalidDataException>(() => session.RefreshAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Throws<IOException>(() => session.CurrentTiming); Assert.Throws<IOException>(() => session.Current);
        Assert.Equal(2, f.Store.State.Revision);
    }
}
