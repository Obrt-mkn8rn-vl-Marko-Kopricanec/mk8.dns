using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SnapshotPathTests
{
    [Theory]
    [InlineData("read")]
    [InlineData("count")]
    [InlineData("activate")]
    public async Task RegularFileAtZonePathFailsClosedWithoutMutation(string operation)
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        using var store = new FileZoneSnapshotStore(root);
        var zoneId = Guid.NewGuid();
        var zonePath = Path.Combine(root, zoneId.ToString("N"));
        byte[] original = [11, 22, 33];
        await File.WriteAllBytesAsync(zonePath, original, CancellationToken.None).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<IOException>(() => ExecuteAsync(store, zoneId, operation)).ConfigureAwait(true);
        Assert.Equal(original, await File.ReadAllBytesAsync(zonePath, CancellationToken.None).ConfigureAwait(true));
        Assert.False(Directory.Exists(zonePath));
    }

    [Theory]
    [InlineData("read")]
    [InlineData("count")]
    [InlineData("activate")]
    public async Task NonDirectoryAncestorIsNotTreatedAsMissingStorage(string operation)
    {
        using var directory = new TemporaryDirectory();
        var parent = Path.Combine(directory.Path, "parent");
        Directory.CreateDirectory(parent);
        using var store = new FileZoneSnapshotStore(Path.Combine(parent, "state"));
        Directory.Delete(parent, recursive: true);
        byte[] original = [44, 55, 66];
        await File.WriteAllBytesAsync(parent, original, CancellationToken.None).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<IOException>(() => ExecuteAsync(store, Guid.NewGuid(), operation)).ConfigureAwait(true);
        Assert.Equal(original, await File.ReadAllBytesAsync(parent, CancellationToken.None).ConfigureAwait(true));
        Assert.False(Directory.Exists(parent));
    }

    [Fact]
    public async Task UnknownRootFileIsNotHiddenByZoneDiscovery()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        using var store = new FileZoneSnapshotStore(root);
        var unexpected = Path.Combine(root, "unexpected");
        await File.WriteAllTextAsync(unexpected, "preserve", CancellationToken.None).ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.CountActiveAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal("preserve", await File.ReadAllTextAsync(unexpected, CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task NoncanonicalZoneDirectoryCannotBeCountedAsAbsent()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        using var store = new FileZoneSnapshotStore(root);
        var alternateName = Path.Combine(root, "ABCDEF0123456789ABCDEF0123456789AB");
        Directory.CreateDirectory(alternateName);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.CountActiveAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.True(Directory.Exists(alternateName));
    }

    private static Task ExecuteAsync(FileZoneSnapshotStore store, Guid zoneId, string operation) => operation switch
    {
        "read" => store.ReadActiveAsync(zoneId, CancellationToken.None).AsTask(),
        "count" => store.CountActiveAsync(CancellationToken.None).AsTask(),
        "activate" => store.ActivateAsync(new ZoneSnapshot(zoneId, DnsName.Parse("example.org."), 1, 1, [1]), CancellationToken.None).AsTask(),
        _ => throw new ArgumentException("Unknown storage operation.", nameof(operation)),
    };
}
