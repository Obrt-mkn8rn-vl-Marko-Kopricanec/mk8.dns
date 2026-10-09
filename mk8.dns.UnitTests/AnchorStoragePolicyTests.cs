using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorStoragePolicyTests
{
    [Fact]
    public void AuthenticationKeyIsClonedAndCallerMutationCannotChangeStorageIdentity()
    {
        using var f = new AnchorStorageFixture();
        var key = (byte[])f.Secret.Clone();
        using var store = FileAnchorCheckpointStore.Create(f.Root, f.Identity, f.Keys.Tracker(f.Keys.A), key);
        Array.Clear(key);
        Assert.Equal(2, store.Save(1));
        store.Dispose();
        using var restored = f.Open(2);
        Assert.Equal(2, restored.Revision);
    }

    [Fact]
    public void ExpectedRevisionAndPreAdmissionCancellationDoNotMutateStorage()
    {
        using var f = new AnchorStorageFixture();
        using var store = f.Create();
        var before = f.Image();
        Assert.Throws<InvalidOperationException>(() => store.Save(0));
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => store.Save(1, canceled.Token));
        Assert.Equal(before, f.Image());
        Assert.Equal(2, store.Save(1));
    }

    [Theory]
    [InlineData("key")]
    [InlineData("identity")]
    [InlineData("origin")]
    public void ScopeOrSecretMismatchRefusesWithoutChangingAcknowledgedFiles(string mismatch)
    {
        using var f = new AnchorStorageFixture();
        using (f.Create()) { }
        var key = (byte[])f.Secret.Clone(); if (string.Equals(mismatch, "key", StringComparison.Ordinal)) key[0] ^= 1;
        var id = string.Equals(mismatch, "identity", StringComparison.Ordinal) ? Guid.NewGuid() : f.Identity;
        var origin = string.Equals(mismatch, "origin", StringComparison.Ordinal) ? DnsName.Parse("other.") : f.Keys.Origin;
        var before = f.Image();
        Assert.Throws<InvalidDataException>(() =>
        { using var ignored = FileAnchorCheckpointStore.Open(f.Root, id, origin, key, 1, DnssecFixture.Verifier, f.Keys.Clock); });
        Assert.Equal(before, f.Image());
        using var recovered = f.Open(); Assert.Equal(1, recovered.Revision);
    }

    [Fact]
    public void RetentionCapacityFailsBeforeMutationAndCannotResetHistoryByReopening()
    {
        using var f = new AnchorStorageFixture();
        using var store = f.Create();
        for (var revision = 1; revision < FileAnchorCheckpointStore.MaximumGenerations; revision++)
            Assert.Equal(revision + 1, store.Save(revision));
        var before = f.Image();
        Assert.Throws<IOException>(() => store.Save(FileAnchorCheckpointStore.MaximumGenerations));
        Assert.Equal(before, f.Image());
        store.Dispose();
        using var restored = f.Open(FileAnchorCheckpointStore.MaximumGenerations);
        Assert.Equal(FileAnchorCheckpointStore.MaximumGenerations, restored.Revision);
        Assert.Throws<IOException>(() => restored.Save(restored.Revision));
    }

    [Fact]
    public void DisposedOwnerRejectsWorkAndSuccessorMustUseExistingRecovery()
    {
        using var f = new AnchorStorageFixture();
        var store = f.Create(); store.Dispose(); store.Dispose();
        Assert.Throws<ObjectDisposedException>(() => store.Save(1));
        Assert.Throws<ObjectDisposedException>(() => store.Tracker);
        Assert.Throws<InvalidDataException>(() => { using var ignored = f.Create(); });
        using var successor = f.Open(); Assert.Equal(2, successor.Save(1));
    }
}
