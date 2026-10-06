using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SnapshotStoreTests
{
    [Fact]
    public async Task ActivationSurvivesReopeningAndRetainsPreviousGeneration()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        var zoneId = Guid.NewGuid();
        using (var store = new FileZoneSnapshotStore(root))
        {
            await store.ActivateAsync(Snapshot(zoneId, 1, uint.MaxValue, 1), TestContextToken).ConfigureAwait(true);
            await store.ActivateAsync(Snapshot(zoneId, 2, 0, 2), TestContextToken).ConfigureAwait(true);
        }
        using var restarted = new FileZoneSnapshotStore(root);
        var active = await restarted.ReadActiveAsync(zoneId, TestContextToken).ConfigureAwait(true);
        Assert.NotNull(active);
        Assert.Equal(2, active.Revision);
        Assert.Equal(0u, active.Serial);
        Assert.Equal(new byte[] { 2 }, active.GetPayload());
        Assert.True(File.Exists(Path.Combine(root, zoneId.ToString("N"), "previous.json")));
        Assert.Equal(1u, await restarted.CountActiveAsync(TestContextToken).ConfigureAwait(true));
    }

    [Fact]
    public async Task DuplicateActivationIsIdempotentAndConflictingActivationPreservesState()
    {
        using var directory = new TemporaryDirectory();
        using var store = new FileZoneSnapshotStore(Path.Combine(directory.Path, "state"));
        var zoneId = Guid.NewGuid();
        var original = Snapshot(zoneId, 10, 100, 1);
        await store.ActivateAsync(original, TestContextToken).ConfigureAwait(true);
        await store.ActivateAsync(original, TestContextToken).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.ActivateAsync(Snapshot(zoneId, 10, 101, 2), TestContextToken).AsTask()).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.ActivateAsync(Snapshot(zoneId, 11, 99, 2), TestContextToken).AsTask()).ConfigureAwait(true);
        var active = await store.ReadActiveAsync(zoneId, TestContextToken).ConfigureAwait(true);
        Assert.NotNull(active);
        Assert.Equal(original.ContentHash, active.ContentHash);
    }

    [Fact]
    public async Task CancellationDoesNotChangeTheActiveGeneration()
    {
        using var directory = new TemporaryDirectory();
        using var store = new FileZoneSnapshotStore(Path.Combine(directory.Path, "state"));
        var zoneId = Guid.NewGuid();
        await store.ActivateAsync(Snapshot(zoneId, 1, 1, 1), TestContextToken).ConfigureAwait(true);
        using var canceled = new CancellationTokenSource();
        await canceled.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.ActivateAsync(Snapshot(zoneId, 2, 2, 2), canceled.Token).AsTask()).ConfigureAwait(true);
        var active = await store.ReadActiveAsync(zoneId, TestContextToken).ConfigureAwait(true);
        Assert.NotNull(active);
        Assert.Equal(1, active.Revision);
    }

    [Fact]
    public async Task TamperedBundleFailsClosed()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        using var store = new FileZoneSnapshotStore(root);
        var zoneId = Guid.NewGuid();
        await store.ActivateAsync(Snapshot(zoneId, 1, 1, 1), TestContextToken).ConfigureAwait(true);
        var files = Directory.GetFiles(Path.Combine(root, zoneId.ToString("N")), "1-*.json");
        Assert.Single(files);
        await File.WriteAllTextAsync(files[0], "{}", TestContextToken).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadActiveAsync(zoneId, TestContextToken).AsTask()).ConfigureAwait(true);
    }

    [Fact]
    public async Task SymbolicPointerCannotEscapeTheStore()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        using var store = new FileZoneSnapshotStore(root);
        var zoneId = Guid.NewGuid();
        await store.ActivateAsync(Snapshot(zoneId, 1, 1, 1), TestContextToken).ConfigureAwait(true);
        var pointer = Path.Combine(root, zoneId.ToString("N"), "active.json");
        File.Delete(pointer);
        File.CreateSymbolicLink(pointer, Path.Combine(directory.Path, "absent.json"));
        await Assert.ThrowsAsync<IOException>(() => store.ReadActiveAsync(zoneId, TestContextToken).AsTask()).ConfigureAwait(true);
    }

    [Fact]
    public void ASecondWriterAndUnsafeDirectoryAreRejected()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        using var store = new FileZoneSnapshotStore(root);
        Assert.Throws<IOException>(() => new FileZoneSnapshotStore(root));
        var unsafeRoot = Path.Combine(directory.Path, "unsafe");
        Directory.CreateDirectory(unsafeRoot, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherRead);
        File.SetUnixFileMode(unsafeRoot, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherRead);
        Assert.Throws<IOException>(() => new FileZoneSnapshotStore(unsafeRoot));
    }

    private static CancellationToken TestContextToken => CancellationToken.None;
    private static ZoneSnapshot Snapshot(Guid zoneId, long revision, uint serial, byte value) => new(zoneId, DnsName.Parse("example.org."), revision, serial, [value]);
}
