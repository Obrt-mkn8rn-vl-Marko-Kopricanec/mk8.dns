using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorStorageRecoveryTests
{
    [Fact]
    public void SavedPendingStateRequiresFreshProofAfterRestart()
    {
        using var f = new AnchorStorageFixture();
        using (var store = f.Create(AnchorCheckpointFixture.Pending(f.Keys))) Assert.Equal(1, store.Revision);
        f.Keys.Clock.Advance(TimeSpan.FromDays(90).TotalSeconds);
        using var restored = f.Open();
        Assert.Equal(DnssecAnchorState.AddPending, TrustAnchorFixture.Status(restored.Tracker, f.Keys.Key(f.Keys.B)).State);
        f.Keys.Clock.Advance(TimeSpan.FromDays(30).TotalSeconds);
        Assert.Single(restored.Tracker.GetTrustAnchors());
        DnsRecord[] records = [f.Keys.Key(f.Keys.A), f.Keys.Key(f.Keys.B)];
        Assert.True(TrustAnchorFixture.Apply(restored.Tracker, records, f.Keys.Sign(records, f.Keys.A)));
        Assert.Equal(2, restored.Save(1));
        restored.Dispose();
        using var final = f.Open(2);
        Assert.Equal(2, final.Tracker.GetTrustAnchors().Count);
    }

    [Fact]
    public void PermanentRevocationAndEmptyTrustSurviveDiskRecovery()
    {
        using var f = new AnchorStorageFixture();
        using (var store = f.Create())
        {
            var revoked = TrustAnchorFixture.Revoke(f.Keys.Key(f.Keys.A));
            Assert.True(TrustAnchorFixture.Apply(store.Tracker, [revoked], f.Keys.Sign([revoked], f.Keys.A, revoked)));
            Assert.Equal(2, store.Save(1));
        }
        using var recovered = f.Open(2);
        Assert.Empty(recovered.Tracker.GetTrustAnchors());
        Assert.Equal(DnssecAnchorState.Revoked, Assert.Single(recovered.Tracker.GetStatus()).State);
        DnsRecord[] normal = [f.Keys.Key(f.Keys.A)];
        Assert.False(TrustAnchorFixture.Apply(recovered.Tracker, normal, f.Keys.Sign(normal, f.Keys.A)));
        Assert.Empty(recovered.Tracker.GetTrustAnchors());
    }

    [Fact]
    public void PointerRollbackCannotHideSurvivingLaterGeneration()
    {
        using var f = new AnchorStorageFixture();
        byte[] old;
        using (var store = f.Create()) { old = File.ReadAllBytes(f.Head); Assert.Equal(2, store.Save(1)); }
        AnchorStorageFixture.Write(f.Head, old);
        var before = f.Image();
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(); });
        Assert.Equal(before, f.Image());
    }

    [Fact]
    public void TrustedExternalFloorRejectsCompleteOldGenerationSet()
    {
        using var f = new AnchorStorageFixture();
        byte[] old;
        using (var store = f.Create()) { old = File.ReadAllBytes(f.Head); Assert.Equal(2, store.Save(1)); }
        File.Delete(f.Generation(2)); AnchorStorageFixture.Write(f.Head, old);
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(2); });
        // Losing or rolling back the external floor is deliberately outside this store's protection.
        using var oldFloor = f.Open(1);
        Assert.Equal(1, oldFloor.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SurvivingInitializationMarkerForbidsFreshBootstrapAfterMetadataLoss(bool deleteGenerations)
    {
        using var f = new AnchorStorageFixture();
        using (f.Create()) { }
        File.Delete(f.Head);
        if (deleteGenerations) File.Delete(f.Generation(1));
        var before = f.Image();
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Create(); });
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(); });
        Assert.Equal(before, f.Image());
    }

    [Fact]
    public void TamperingFaultsCurrentOwnerBeforeAnyNewGeneration()
    {
        using var f = new AnchorStorageFixture();
        using var store = f.Create();
        var original = File.ReadAllBytes(f.Head); var corrupt = (byte[])original.Clone(); corrupt[^1] ^= 1;
        AnchorStorageFixture.Write(f.Head, corrupt);
        Assert.Throws<InvalidDataException>(() => store.Save(1));
        Assert.False(File.Exists(f.Generation(2)));
        AnchorStorageFixture.Write(f.Head, original);
        Assert.Throws<IOException>(() => store.Save(1));
        Assert.Throws<IOException>(() => store.Revision);
        store.Dispose();
        using var recovered = f.Open();
        Assert.Equal(2, recovered.Save(1));
    }
}
