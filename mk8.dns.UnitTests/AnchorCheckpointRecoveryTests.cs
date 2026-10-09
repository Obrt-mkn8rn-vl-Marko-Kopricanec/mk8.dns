using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorCheckpointRecoveryTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(4_000_000)]
    public void OfflineTimeNeverSpendsUnfinishedHoldDown(long downtime)
    {
        using var f = new TrustAnchorFixture();
        var tracker = AnchorCheckpointFixture.Pending(f);
        f.Clock.Advance(100);
        var checkpoint = tracker.CreateCheckpoint();
        var fresh = new DnssecChainFixture.ClockProvider(); fresh.SetWall(200 + downtime);
        var restored = AnchorCheckpointFixture.Restore(f, checkpoint, fresh);
        var pending = f.Key(f.B);
        Assert.Equal(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(100), TrustAnchorFixture.Status(restored, pending).AddHoldDownRemaining);
        fresh.Advance(2_592_000 - 101);
        Assert.Equal(TimeSpan.FromSeconds(1), TrustAnchorFixture.Status(restored, pending).AddHoldDownRemaining);
        Assert.Single(restored.GetTrustAnchors());
        fresh.Advance(1);
        Assert.Equal(TimeSpan.Zero, TrustAnchorFixture.Status(restored, pending).AddHoldDownRemaining);
        Assert.Single(restored.GetTrustAnchors());
    }

    [Fact]
    public void WallRollbackAndMonotonicRollbackCannotSpendOrReviveTime()
    {
        using var f = new TrustAnchorFixture();
        var tracker = AnchorCheckpointFixture.Pending(f); f.Clock.Advance(100);
        var clock = new DnssecChainFixture.ClockProvider(); clock.SetWall(0);
        var restored = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint(), clock);
        clock.SetMonotonic(1000);
        Assert.Equal(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(100), TrustAnchorFixture.Status(restored, f.Key(f.B)).AddHoldDownRemaining);
        clock.SetWall(210);
        Assert.Equal(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(110), TrustAnchorFixture.Status(restored, f.Key(f.B)).AddHoldDownRemaining);
        clock.SetWall(0); clock.SetMonotonic(0);
        Assert.Equal(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(110), TrustAnchorFixture.Status(restored, f.Key(f.B)).AddHoldDownRemaining);
    }

    [Fact]
    public void RepeatedRestartPreservesRemainingAndNeedsFreshAuthentication()
    {
        using var f = new TrustAnchorFixture();
        var tracker = AnchorCheckpointFixture.Pending(f);
        f.Clock.Advance(10);
        tracker = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        f.Clock.Advance(20);
        tracker = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        Assert.Equal(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(30), TrustAnchorFixture.Status(tracker, f.Key(f.B)).AddHoldDownRemaining);
        f.Clock.Advance(2_592_000 - 30);
        tracker = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        Assert.Single(tracker.GetTrustAnchors());
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        var bad = f.Sign(records, f.A).GetData(); bad[^1] ^= 1;
        Assert.False(TrustAnchorFixture.Apply(tracker, records, new DnsRecord(f.Origin, 46, 3600, bad)));
        Assert.Single(tracker.GetTrustAnchors());
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(2, tracker.GetTrustAnchors().Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FirstSponsorRevocationHistorySurvivesBeforeAndAfterExpiry(bool expire)
    {
        using var f = new TrustAnchorFixture();
        var tracker = AnchorCheckpointFixture.Pending(f, bothSponsors: true);
        f.Clock.Advance(10);
        var a = TrustAnchorFixture.Revoke(f.Key(f.A));
        DnsRecord[] records = [a, f.Key(f.B), f.Key(f.C)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, a), f.Sign(records, f.B)));
        tracker = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        f.Clock.Advance(2_592_000 - (expire ? 10 : 11));
        var b = TrustAnchorFixture.Revoke(f.Key(f.B));
        DnsRecord[] revoked = [a, b, f.Key(f.C)];
        Assert.True(TrustAnchorFixture.Apply(tracker, revoked, f.Sign(revoked, f.B, b)));
        Assert.Empty(tracker.GetTrustAnchors());
        Assert.Equal(expire ? 3 : 2, tracker.GetStatus().Count);
        if (expire) Assert.Equal(DnssecAnchorState.AddPending, TrustAnchorFixture.Status(tracker, f.Key(f.C)).State);
    }

    [Fact]
    public void OriginalTtlLongerThanThirtyDaysRemainsUnspentAcrossRestart()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, originalTtl: 4_000_000)));
        f.Clock.Advance(100);
        tracker = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        Assert.Equal(TimeSpan.FromSeconds(3_999_900), TrustAnchorFixture.Status(tracker, f.Key(f.B)).AddHoldDownRemaining);
    }
}
