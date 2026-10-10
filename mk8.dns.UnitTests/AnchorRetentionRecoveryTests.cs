using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRetentionRecoveryTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void RecoveryRequiresAFloorCoveringTheAuthenticatedBoundary(long floor)
    {
        using var f = new AnchorRetentionFixture();
        using (var store = f.Create()) { AnchorRetentionFixture.Advance(store, 4); Assert.Equal(3, store.Retain(4, 4, 2)); }
        var before = f.Storage.Image();
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(floor); });
        Assert.Equal(before, f.Storage.Image());
        using var restored = f.Open(4); Assert.Equal(5, restored.Save(4));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(4)]
    public void MissingRetainedGenerationCannotBecomeAResetOrFallback(long missing)
    {
        using var f = new AnchorRetentionFixture();
        using (var store = f.Create()) { AnchorRetentionFixture.Advance(store, 4); _ = store.Retain(4, 4, 2); }
        File.Delete(f.Storage.Generation(missing)); var before = f.Storage.Image();
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(4); });
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Create(); });
        Assert.Equal(before, f.Storage.Image());
    }

    [Fact]
    public void SurvivingLaterOrphanStillRefusesRecoveryAfterRetention()
    {
        using var f = new AnchorRetentionFixture(); byte[] old;
        using (var store = f.Create())
        {
            AnchorRetentionFixture.Advance(store, 4); _ = store.Retain(4, 4, 2);
            old = File.ReadAllBytes(f.Storage.Head); Assert.Equal(5, store.Save(4));
        }
        AnchorStorageFixture.Write(f.Storage.Head, old);
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Open(4); });
    }

    [Fact]
    public void PointerBoundaryRollbackFaultsLiveOwnerEvenWhenLogicalHeadIsUnchanged()
    {
        using var f = new AnchorRetentionFixture(); using var store = f.Create();
        AnchorRetentionFixture.Advance(store, 4);
        var oldPointer = File.ReadAllBytes(f.Storage.Head); var oldFirst = File.ReadAllBytes(f.Storage.Generation(1));
        var oldSecond = File.ReadAllBytes(f.Storage.Generation(2));
        Assert.Equal(3, store.Retain(4, 4, 2));
        AnchorStorageFixture.Write(f.Storage.Generation(1), oldFirst); AnchorStorageFixture.Write(f.Storage.Generation(2), oldSecond);
        AnchorStorageFixture.Write(f.Storage.Head, oldPointer);
        Assert.Throws<InvalidDataException>(() => store.Save(4));
        Assert.False(File.Exists(f.Storage.Generation(5))); Assert.Throws<IOException>(() => store.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DistinctStoreFormatsRequireExplicitCorrectOpenMode(bool retention)
    {
        using var f = new AnchorRetentionFixture();
        using (retention ? f.Create() : f.Storage.Create()) { }
        var before = f.Storage.Image();
        Assert.Throws<InvalidDataException>(() =>
        {
            using var ignored = retention ? f.Storage.Open() : f.Open(1);
        });
        Assert.Equal(before, f.Storage.Image());
        using var correct = retention ? f.Open(1) : f.Storage.Open(); Assert.Equal(2, correct.Save(1));
    }

    [Fact]
    public void RetentionKeepsRevocationTombstonesThroughRecovery()
    {
        using var f = new AnchorRetentionFixture();
        var tracker = AnchorCheckpointFixture.Pending(f.Storage.Keys);
        var revoked = TrustAnchorFixture.Revoke(f.Storage.Keys.Key(f.Storage.Keys.A));
        Assert.True(TrustAnchorFixture.Apply(tracker, [revoked], f.Storage.Keys.Sign([revoked], f.Storage.Keys.A, revoked)));
        using (var store = FileAnchorCheckpointStore.CreateWithRetention(f.Storage.Root, f.Storage.Identity, tracker, f.Storage.Secret))
        {
            Assert.Equal(2, store.Save(1)); Assert.Equal(2, store.Retain(2, 2, 1));
        }
        using var recovered = f.Open(2);
        Assert.Empty(recovered.Tracker.GetTrustAnchors());
        Assert.Contains(recovered.Tracker.GetStatus(), state => state.State == Mk8.Dns.Engine.Dnssec.DnssecAnchorState.Revoked);
    }

    [Fact]
    public void RetainedPendingHoldStillRequiresFreshAuthenticatedPostRecoveryObservation()
    {
        using var f = new AnchorRetentionFixture();
        using (var store = FileAnchorCheckpointStore.CreateWithRetention(f.Storage.Root, f.Storage.Identity,
            AnchorCheckpointFixture.Pending(f.Storage.Keys), f.Storage.Secret))
        {
            Assert.Equal(2, store.Save(1)); Assert.Equal(2, store.Retain(2, 2, 1));
        }
        f.Storage.Keys.Clock.Advance(TimeSpan.FromDays(90).TotalSeconds);
        using var recovered = f.Open(2); Assert.Single(recovered.Tracker.GetTrustAnchors());
        Assert.Contains(recovered.Tracker.GetStatus(), state => state.State == Mk8.Dns.Engine.Dnssec.DnssecAnchorState.AddPending);
        f.Storage.Keys.Clock.Advance(TimeSpan.FromDays(30).TotalSeconds); Assert.Single(recovered.Tracker.GetTrustAnchors());
        Mk8.Dns.Domain.DnsRecord[] records = [f.Storage.Keys.Key(f.Storage.Keys.A), f.Storage.Keys.Key(f.Storage.Keys.B)];
        Assert.True(TrustAnchorFixture.Apply(recovered.Tracker, records, f.Storage.Keys.Sign(records, f.Storage.Keys.A)));
        Assert.Equal(3, recovered.Save(2)); Assert.Equal(2, recovered.Tracker.GetTrustAnchors().Count);
    }

    [Fact]
    public void LargestRevisionRefusesFurtherCommitWithoutOverflowOrAnyMutation()
    {
        using var f = new AnchorRetentionFixture(); byte[] payload;
        using (var store = f.Create()) payload = ((Mk8.Dns.Engine.Dnssec.IDnssecAnchorCheckpointStore)store).ReadCommitted().GetCheckpoint();
        File.Delete(f.Storage.Generation(1));
        var previous = SHA256.HashData("controlled-pruned-prefix"u8);
        var raw = f.Generation(long.MaxValue, previous, payload);
        AnchorStorageFixture.Write(f.Storage.Generation(long.MaxValue), raw);
        AnchorStorageFixture.Write(f.Storage.Head, f.Pointer(long.MaxValue, long.MaxValue, previous, SHA256.HashData(raw)));
        using var storeAtLimit = f.Open(long.MaxValue); var before = f.Storage.Image();
        Assert.Equal(long.MaxValue, storeAtLimit.Revision);
        Assert.Throws<IOException>(() => storeAtLimit.Save(long.MaxValue));
        Assert.Equal(before, f.Storage.Image());
    }
}
