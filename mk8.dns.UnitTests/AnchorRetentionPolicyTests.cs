using Mk8.Dns.Application.DAL;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRetentionPolicyTests
{
    [Fact]
    public void ExplicitTrustedBoundaryReclaimsCapacityWithoutResettingLogicalRevision()
    {
        using var f = new AnchorRetentionFixture(); using var store = f.Create();
        AnchorRetentionFixture.Advance(store, FileAnchorCheckpointStore.MaximumGenerations);
        var port = (IDnssecAnchorCheckpointStore)store; var before = port.ReadCommitted().GetCheckpoint();
        var image = f.Storage.Image();
        Assert.Throws<IOException>(() => store.Save(256)); Assert.Equal(image, f.Storage.Image());
        Assert.Equal(129, store.Retain(256, 256, 128));
        Assert.Equal(256, store.Revision); Assert.Equal(before, port.ReadCommitted().GetCheckpoint());
        Assert.Equal(128, Directory.EnumerateFiles(f.Storage.Root, "*.anchor").Count());
        Assert.False(File.Exists(f.Storage.Generation(1))); Assert.True(File.Exists(f.Storage.Generation(129)));
        Assert.Equal(257, store.Save(256)); store.Dispose();
        using var successor = f.Open(256);
        Assert.Equal(257, successor.Revision); Assert.Equal(129, successor.FirstRetainedRevision);
        Assert.Equal(258, successor.Save(257));
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(0, 1)]
    [InlineData(2, 0)]
    [InlineData(2, 257)]
    [InlineData(1, 1)]
    [InlineData(4, 1)]
    public void InvalidKeepOrUnacknowledgedFloorCannotChangeFiles(long floor, int keep)
    {
        using var f = new AnchorRetentionFixture(); using var store = f.Create();
        AnchorRetentionFixture.Advance(store, 3); var before = f.Storage.Image();
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Retain(3, floor, keep));
        Assert.Equal(before, f.Storage.Image()); Assert.Equal(3, store.Revision); Assert.Equal(4, store.Save(3));
    }

    [Fact]
    public void WrongRevisionCanceledAdmissionAndLegacyModeDoNotRemoveAnything()
    {
        using var f = new AnchorRetentionFixture(); using var store = f.Create();
        AnchorRetentionFixture.Advance(store, 3); var before = f.Storage.Image();
        Assert.Throws<InvalidOperationException>(() => store.Retain(2, 3, 1));
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => store.Retain(3, 3, 1, canceled.Token));
        Assert.Equal(before, f.Storage.Image()); Assert.Equal(1, store.FirstRetainedRevision);
        using var legacyFixture = new AnchorStorageFixture(); using var legacy = legacyFixture.Create();
        var legacyImage = legacyFixture.Image();
        Assert.Throws<InvalidOperationException>(() => legacy.Retain(1, 1, 1, CancellationToken.None));
        Assert.Equal(legacyImage, legacyFixture.Image());
    }

    [Fact]
    public void RetentionDoesNotPersistMutableUnsavedTrackerOrCreateANewTrustRevision()
    {
        using var f = new AnchorRetentionFixture(); using var store = f.Create();
        AnchorRetentionFixture.Advance(store, 3); var port = (IDnssecAnchorCheckpointStore)store;
        var committed = port.ReadCommitted().GetCheckpoint();
        var revoked = TrustAnchorFixture.Revoke(f.Storage.Keys.Key(f.Storage.Keys.A));
        Assert.True(TrustAnchorFixture.Apply(store.Tracker, [revoked], f.Storage.Keys.Sign([revoked], f.Storage.Keys.A, revoked)));
        Assert.Empty(store.Tracker.GetTrustAnchors());
        Assert.Equal(3, store.Retain(3, 3, 1)); Assert.Equal(3, store.Revision);
        Assert.Equal(committed, port.ReadCommitted().GetCheckpoint()); store.Dispose();
        using var recovered = f.Open(3); Assert.Single(recovered.Tracker.GetTrustAnchors());
    }

    [Fact]
    public void FloorsCannotMoveBackAndIdempotentRetentionDoesNotRestoreDeletedHistory()
    {
        using var f = new AnchorRetentionFixture(); using var store = f.Create();
        AnchorRetentionFixture.Advance(store, 4); Assert.Equal(3, store.Retain(4, 4, 2));
        var before = f.Storage.Image();
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Retain(4, 3, 2));
        Assert.Equal(3, store.Retain(4, 4, 256)); Assert.Equal(before, f.Storage.Image());
        Assert.Equal(3, store.FirstRetainedRevision); Assert.Equal(5, store.Save(4));
    }
}
