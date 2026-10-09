using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorCheckpointLifecycleTests
{
    [Fact]
    public void OutstandingCaptureCannotTransferAcrossRestartAndOriginalRemainsOwned()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(tracker.TryCapture(records, [f.Sign(records, f.A)], out var capture));
        var restored = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        Assert.False(restored.TryApply(capture));
        Assert.Single(restored.GetStatus());
        Assert.True(tracker.TryApply(capture));
        Assert.False(tracker.TryApply(capture));
    }

    [Fact]
    public void ProviderCannotExportPartiallyAppliedStateByReenteringGate()
    {
        using var f = new TrustAnchorFixture();
        DnssecTrustAnchorTracker? tracker = null;
        var attempts = 0;
        var provider = new DnssecChainFixture.CountingVerifier
        {
            AfterVerify = () =>
        {
            Assert.Throws<InvalidOperationException>(() => tracker!.CreateCheckpoint()); attempts++;
        }
        };
        tracker = new DnssecTrustAnchorTracker(f.Origin, [f.Key(f.A)], provider, f.Clock);
        DnsRecord[] records = [f.Key(f.A), f.Key(f.B)];
        Assert.True(TrustAnchorFixture.Apply(tracker, records, f.Sign(records, f.A)));
        Assert.Equal(1, attempts);
        Assert.Equal(2, AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint()).GetStatus().Count);
    }

    [Fact]
    public void TrustedRecoveryDoesNotInvalidatePreviouslyExportedStaticProfiles()
    {
        using var f = new TrustAnchorFixture();
        var tracker = f.Tracker(f.A);
        var prior = Assert.Single(tracker.GetTrustAnchors());
        var revoked = TrustAnchorFixture.Revoke(f.Key(f.A));
        Assert.True(TrustAnchorFixture.Apply(tracker, [revoked], f.Sign([revoked], f.A, revoked)));
        var restored = AnchorCheckpointFixture.Restore(f, tracker.CreateCheckpoint());
        Assert.Empty(restored.GetTrustAnchors());
        var validator = new DnssecChainValidator(DnssecFixture.Verifier, f.Clock);
        DnsRecord[] records = [f.Key(f.A)];
        Assert.True(validator.TryAuthenticateAnchor(prior, records, [f.Sign(records, f.A)], out _));
    }
}
