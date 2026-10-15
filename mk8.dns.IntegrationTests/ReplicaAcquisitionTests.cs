using Mk8.Dns.Application.DAL;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ReplicaAcquisitionTests
{
    [Fact]
    public async Task OrdinaryJournalFailureRollsBackSnapshotLeaseBeforeRemovingOwnedRoot()
    {
        string? acquiredRoot = null;
        var reacquired = false;
        var error = await Assert.ThrowsAsync<IOException>(() => ReplicaFixture.CreateAsync(new ControlFixture(), root =>
        {
            acquiredRoot = root;
            // A regular file cannot serve as the required publication directory.
            File.WriteAllText(Path.Combine(root, "proofs"), "owned wrong-kind journal input");
        }, root =>
        {
            using var replacement = new FileZoneSnapshotStore(Path.Combine(root, "snapshots"));
            reacquired = true;
        })).ConfigureAwait(true);
        Assert.NotNull(error);
        Assert.True(reacquired);
        Assert.NotNull(acquiredRoot);
        Assert.False(Directory.Exists(acquiredRoot));
    }
}
