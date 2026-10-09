using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustAnchorAdditionTests
{
    [Fact]
    public void FreshAuthenticatedObservationAfterHoldDownAddsKey()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(DnssecAnchorState.AddPending, TrustAnchorFixture.Status(tracker, records[1]).State);
        f.Clock.Advance(TimeSpan.FromDays(30).TotalSeconds - 1);
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Single(tracker.GetTrustAnchors());
        f.Clock.Advance(1);
        Assert.Single(tracker.GetTrustAnchors());
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(2, tracker.GetTrustAnchors().Count);
        Assert.Equal(DnssecAnchorState.Valid, TrustAnchorFixture.Status(tracker, records[1]).State);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void OneClockAloneCannotCompleteHoldDown(bool wallOnly)
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        if (wallOnly) f.Clock.SetWall(100 + 2_592_000);
        else f.Clock.SetMonotonic(2_592_000);
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Single(tracker.GetTrustAnchors());
        Assert.Equal(TimeSpan.FromDays(30), TrustAnchorFixture.Status(tracker, records[1]).AddHoldDownRemaining);
    }

    [Fact]
    public void FirstOriginalTtlCanExtendHoldDown()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, originalTtl: 3_000_000)));
        f.Clock.Advance(2_592_000);
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Single(tracker.GetTrustAnchors());
        f.Clock.Advance(408_000);
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(2, tracker.GetTrustAnchors().Count);
    }

    [Fact]
    public void AuthenticatedAbsenceResetsPendingButRetainsMissingAnchor()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A, f.C);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B), f.Key(f.C)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        f.Clock.Advance(2_592_000);
        DnsRecord[] absent = [records[0]];
        Assert.True(TrustAnchorFixture.Apply(tracker, absent, f.Sign(absent, f.A)));
        Assert.Equal(2, tracker.GetStatus().Count);
        Assert.Equal(DnssecAnchorState.Missing, TrustAnchorFixture.Status(tracker, records[2]).State);
        Assert.Equal(2, tracker.GetTrustAnchors().Count);
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(TimeSpan.FromDays(30), TrustAnchorFixture.Status(tracker, records[1]).AddHoldDownRemaining);
        Assert.Equal(DnssecAnchorState.Valid, TrustAnchorFixture.Status(tracker, records[2]).State);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NewOrNonSepSignerCannotBootstrapTrust(bool nonSep)
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B, sep: !nonSep)];
        Assert.False(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.B, records[1])));
        Assert.Single(tracker.GetStatus());
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(nonSep ? 1 : 2, tracker.GetStatus().Count);
    }

    [Fact]
    public void HeldAndRepeatedCapturesCannotSupplyFreshPostHoldDownObservation()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        var signature = f.Sign(records, f.A, expiration: 4_000_000);
        Assert.True(tracker.TryCapture(records, [signature], out var first));
        Assert.True(tracker.TryApply(first));
        Assert.True(tracker.TryCapture(records, [signature], out var held));
        f.Clock.Advance(2_592_000);
        Assert.False(tracker.TryApply(first));
        Assert.False(tracker.TryApply(held));
        Assert.Single(tracker.GetTrustAnchors());
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(2, tracker.GetTrustAnchors().Count);
    }
}
