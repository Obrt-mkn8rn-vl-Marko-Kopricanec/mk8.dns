using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRefreshStagingTests
{
    [Fact]
    public void StagingDoesNotShareCapturesOrMutableTrustEntries()
    {
        using var f = new TrustAnchorFixture(); var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)]; var signature = f.Sign(records, f.A);
        Assert.True(tracker.TryCapture(records, [signature], out var capture));
        var staged = tracker.CreateStagedTracker();
        Assert.False(staged.TryApply(capture));
        Assert.True(TrustAnchorFixture.Apply(staged, records, signature));
        Assert.Single(tracker.GetStatus()); Assert.Equal(2, staged.GetStatus().Count);
        Assert.True(tracker.TryApply(capture));
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A));
        Assert.True(TrustAnchorFixture.Apply(staged, [revoked], f.Sign([revoked], f.A, revoked)));
        Assert.Empty(staged.GetTrustAnchors()); Assert.Single(tracker.GetTrustAnchors());
        Assert.Equal(DnssecAnchorState.AddPending, TrustAnchorFixture.Status(tracker, f.Key(f.B)).State);
    }

    [Fact]
    public void LiveStagingPreservesUnequalClockProgressAndDoesNotActLikeRecovery()
    {
        using var f = new TrustAnchorFixture(); var tracker = AnchorCheckpointFixture.Pending(f);
        f.Clock.SetMonotonic(TimeSpan.FromDays(31).TotalSeconds);
        var staged = tracker.CreateStagedTracker();
        Assert.Equal(TimeSpan.FromDays(30), TrustAnchorFixture.Status(staged, f.Key(f.B)).AddHoldDownRemaining);
        f.Clock.SetWall(100 + (long)TimeSpan.FromDays(31).TotalSeconds);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(staged, records, f.Sign(records, f.A)));
        Assert.Equal(2, staged.GetTrustAnchors().Count); Assert.Single(tracker.GetTrustAnchors());
    }
}
