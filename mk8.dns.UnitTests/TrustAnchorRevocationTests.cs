using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustAnchorRevocationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SelfSignedRevocationRemovesValidOrMissingKeyPermanently(bool missing)
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A, f.B);
        if (missing)
        {
            DnsRecord[] onlyB = [f.Key(f.B)];
            Assert.True(TrustAnchorFixture.Apply(tracker, onlyB, f.Sign(onlyB, f.B)));
        }
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A));
        DnsRecord[] records = [revoked, f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, revoked), f.Sign(records, f.B)));
        Assert.Equal(DnssecAnchorState.Revoked, TrustAnchorFixture.Status(tracker, f.Key(f.A)).State);
        Assert.Single(tracker.GetTrustAnchors());
        DnsRecord[] restored = [f.Key(f.A), f.Key(f.B)];
        f.Clock.Advance(4_000_000);
        Assert.True(TrustAnchorFixture.Apply(tracker, restored, f.Sign(restored, f.B)));
        Assert.Single(tracker.GetTrustAnchors());
    }

    [Fact]
    public void AnotherAnchorCannotRevokeKeyWithoutItsSelfSignature()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A, f.B);
        DnsRecord[] records = [TrustAnchorFixture.Revoke(f.Key(f.A)), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.B)));
        Assert.Equal(DnssecAnchorState.Missing, TrustAnchorFixture.Status(tracker, f.Key(f.A)).State);
        Assert.Equal(2, tracker.GetTrustAnchors().Count);
    }

    [Fact]
    public void SoleAnchorSelfRevocationDoesNotBootstrapReplacement()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A));
        DnsRecord[] records = [revoked, f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, revoked)));
        Assert.Empty(tracker.GetTrustAnchors());
        Assert.Single(tracker.GetStatus());
        Assert.False(TrustAnchorFixture.Apply(tracker, [records[1]], f.Sign([records[1]], f.B)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OriginalSponsorsAreAllRememberedAndResetOnlyBeforeExpiry(bool bothRevoked)
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A, f.B);
        DnsRecord[] initial = [f.Key(f.A), f.Key(f.B), f.Key(f.C)];
        Assert.True(TrustAnchorFixture.Apply(tracker, initial, f.Sign(initial, f.A), f.Sign(initial, f.B)));
        f.Clock.Advance(10);
        var revokedA = TrustAnchorFixture.Revoke(initial[0]);
        var keyB = bothRevoked ? TrustAnchorFixture.Revoke(initial[1]) : initial[1];
        DnsRecord[] records = [revokedA, keyB, initial[2]];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A, revokedA), f.Sign(records, f.B, keyB)));
        Assert.Equal(bothRevoked ? 2 : 3, tracker.GetStatus().Count);
        Assert.Equal(bothRevoked ? 0 : 1, tracker.GetTrustAnchors().Count);
        if (!bothRevoked)
        {
            f.Clock.Advance(2_592_000);
            Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.B)));
            Assert.Equal(2, tracker.GetTrustAnchors().Count);
        }
    }

    [Fact]
    public void RevokedKeyStillFailsGeneralVerifierAndStaticAnchorAdmission()
    {
        using var f = new TrustAnchorFixture();
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A));
        DnsRecord[] records = [revoked];
        var signature = f.Sign(records, f.A, revoked);
        Assert.False(DnssecRrsetVerifier.TryVerify(records, signature, revoked, 100, DnssecFixture.Verifier, out _));
        Assert.Throws<ArgumentException>(() => new DnssecTrustAnchor(revoked));
        Assert.Throws<ArgumentException>(() => f.Tracker());
    }
}
