using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustAnchorPolicyTests
{
    [Fact]
    public void AbsentAcceptedKeyCanStillAuthenticateCompleteKeyset()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(DnssecAnchorState.Missing, TrustAnchorFixture.Status(tracker, f.Key(f.A)).State);
        f.Clock.Advance(2_592_000);
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(2, tracker.GetTrustAnchors().Count);
    }

    [Fact]
    public void AuthenticatedRevocationBeforeExpiryResetsFirstSponsorTimer()
    {
        using var f = new TrustAnchorFixture();
        var verifier = new DnssecChainFixture.CountingVerifier();
        var tracker = new DnssecTrustAnchorTracker(f.Origin, [f.Key(f.A), f.Key(f.B)], verifier, f.Clock);
        DnsRecord[] initial = [f.Key(f.A), f.Key(f.B), f.Key(f.C)];
        Assert.True(TrustAnchorFixture.Apply(tracker, initial, f.Sign(initial, f.A)));
        f.Clock.Advance(2_592_000 - 1);
        var revoked = TrustAnchorFixture.Revoke(initial[0]);
        DnsRecord[] records = [revoked, initial[1], initial[2]];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, revoked), f.Sign(records, f.B)));
        Assert.Equal(TimeSpan.FromDays(30), TrustAnchorFixture.Status(tracker, initial[2]).AddHoldDownRemaining);
    }

    [Fact]
    public void ExpiredHoldDownStillNeedsSurvivingAnchorOnFreshObservation()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] initial = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, initial, f.Sign(initial, f.A)));
        f.Clock.Advance(2_592_000);
        var revoked = TrustAnchorFixture.Revoke(initial[0]);
        DnsRecord[] records = [revoked, initial[1]];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, revoked), f.Sign(records, f.B)));
        Assert.Empty(tracker.GetTrustAnchors());
        Assert.Equal(DnssecAnchorState.AddPending, TrustAnchorFixture.Status(tracker, initial[1]).State);
    }

    [Fact]
    public void BackwardSamplesCannotReviveOrResetCompletedTime()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        f.Clock.Advance(100);
        Assert.Equal(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(100), TrustAnchorFixture.Status(tracker, records[1]).AddHoldDownRemaining);
        f.Clock.SetWall(100);
        f.Clock.SetMonotonic(0);
        Assert.Equal(TimeSpan.FromDays(30) - TimeSpan.FromSeconds(100), TrustAnchorFixture.Status(tracker, records[1]).AddHoldDownRemaining);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void ConstructorRequiresExplicitUsableSepTrust(int scenario)
    {
        using var f = new TrustAnchorFixture();
        var key = scenario switch
        {
            0 => f.Key(f.A, sep: false),
            1 => TrustAnchorFixture.Revoke(f.Key(f.A)),
            _ => DnssecKeys.CreateDs(f.Key(f.A), 3600),
        };
        Assert.Throws<ArgumentException>(() => new DnssecTrustAnchorTracker(f.Origin, [key], DnssecFixture.Verifier));
    }
}
