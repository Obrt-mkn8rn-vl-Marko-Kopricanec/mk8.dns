using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SnapshotRecoveryTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task MissingActiveMetadataCannotResetAcknowledgedState(bool retainPrevious, bool onlyPreviousRemains)
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        var zoneId = Guid.NewGuid();
        using (var store = new FileZoneSnapshotStore(root))
        {
            await store.ActivateAsync(Snapshot(zoneId, 10, 10), CancellationToken.None).ConfigureAwait(true);
            if (retainPrevious)
                await store.ActivateAsync(Snapshot(zoneId, 11, 11), CancellationToken.None).ConfigureAwait(true);
        }
        var zoneDirectory = Path.Combine(root, zoneId.ToString("N"));
        var pointer = Path.Combine(zoneDirectory, "active.json");
        File.Delete(pointer);
        if (onlyPreviousRemains)
            foreach (var file in Directory.GetFiles(zoneDirectory, "*-*.json"))
                File.Delete(file);
        var remaining = Directory.GetFiles(zoneDirectory);
        Assert.Equal(retainPrevious, File.Exists(Path.Combine(zoneDirectory, "previous.json")));

        using var reopened = new FileZoneSnapshotStore(root);
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadActiveAsync(zoneId, CancellationToken.None).AsTask()).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.CountActiveAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        var attempted = new[]
        {
            Snapshot(zoneId, 1, 1),
            Snapshot(zoneId, 10, 12),
            Snapshot(zoneId, 12, 1),
            Snapshot(zoneId, 12, 12, "different.org."),
            Snapshot(zoneId, 12, 12),
        };
        foreach (var snapshot in attempted)
            await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ActivateAsync(snapshot, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.False(File.Exists(pointer));
        Assert.Equal(remaining.Order(StringComparer.Ordinal), Directory.GetFiles(zoneDirectory).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task UnpublishedStorageCanAcceptItsFirstSnapshot(int interruptedState)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        var zoneId = Guid.NewGuid();
        using (var initial = new FileZoneSnapshotStore(root))
        {
            var zoneDirectory = Path.Combine(root, zoneId.ToString("N"));
            if (interruptedState != 0)
                Directory.CreateDirectory(zoneDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            if (interruptedState == 2)
                await File.WriteAllTextAsync(Path.Combine(zoneDirectory, Guid.NewGuid().ToString("N") + ".tmp"), "incomplete", CancellationToken.None).ConfigureAwait(true);
        }
        using var reopened = new FileZoneSnapshotStore(root);
        Assert.Null(await reopened.ReadActiveAsync(zoneId, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(0u, await reopened.CountActiveAsync(CancellationToken.None).ConfigureAwait(true));
        await reopened.ActivateAsync(Snapshot(zoneId, 1, 1), CancellationToken.None).ConfigureAwait(true);
        var active = await reopened.ReadActiveAsync(zoneId, CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(active);
        Assert.Equal(1, active.Revision);
        Assert.Equal(1u, await reopened.CountActiveAsync(CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task InterruptedFirstPublicationWithACompleteBundleRequiresReconciliation()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        var zoneId = Guid.NewGuid();
        using (var interrupted = new FileZoneSnapshotStore(root, _ => ValueTask.FromException(new IOException("Injected failure before active publication."))))
            await Assert.ThrowsAsync<IOException>(() => interrupted.ActivateAsync(Snapshot(zoneId, 10, 10), CancellationToken.None).AsTask()).ConfigureAwait(true);
        var zoneDirectory = Path.Combine(root, zoneId.ToString("N"));
        Assert.False(File.Exists(Path.Combine(zoneDirectory, "active.json")));
        Assert.Single(Directory.GetFiles(zoneDirectory, "10-*.json"));
        using var reopened = new FileZoneSnapshotStore(root);
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadActiveAsync(zoneId, CancellationToken.None).AsTask()).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.CountActiveAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ActivateAsync(Snapshot(zoneId, 1, 1), CancellationToken.None).AsTask()).ConfigureAwait(true);
    }

    [Fact]
    public async Task ActivePathThatIsNotAFileCannotResetState()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        var zoneId = Guid.NewGuid();
        using var store = new FileZoneSnapshotStore(root);
        await store.ActivateAsync(Snapshot(zoneId, 10, 10), CancellationToken.None).ConfigureAwait(true);
        var pointer = Path.Combine(root, zoneId.ToString("N"), "active.json");
        File.Delete(pointer);
        Directory.CreateDirectory(pointer);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.ReadActiveAsync(zoneId, CancellationToken.None).AsTask()).ConfigureAwait(true);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.CountActiveAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.ActivateAsync(Snapshot(zoneId, 1, 1), CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.True(Directory.Exists(pointer));
    }

    private static ZoneSnapshot Snapshot(Guid zoneId, long revision, uint serial, string origin = "example.org.") => new(zoneId, DnsName.Parse(origin), revision, serial, [1]);
}
