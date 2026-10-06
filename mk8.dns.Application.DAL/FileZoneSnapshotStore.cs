using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.DAL;

public sealed class FileZoneSnapshotStore : IZoneSnapshotStore, IDisposable, IAsyncDisposable
{
    private const int MaximumDocumentBytes = 2_097_152;
    private readonly string root;
    private readonly FileStream writerLease;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Lock lifetimeLock = new();
    private readonly CancellationTokenSource admissionClosed = new();
    private readonly TaskCompletionSource disposalCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Func<CancellationToken, ValueTask>? beforeActivePointerWrite;
    private int operations;
    private bool disposeRequested;
    private bool admissionSignaled;

    public FileZoneSnapshotStore(string root) : this(root, null)
    {
    }

    internal FileZoneSnapshotStore(string root, Func<CancellationToken, ValueTask>? beforeActivePointerWrite)
    {
        ArgumentException.ThrowIfNullOrEmpty(root);
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The durable snapshot prototype requires Linux.");
        if (!Path.IsPathFullyQualified(root))
            throw new ArgumentException("Snapshot storage requires an absolute path.", nameof(root));
        this.root = Path.GetFullPath(root);
        this.beforeActivePointerWrite = beforeActivePointerWrite;
        var parent = Path.GetDirectoryName(this.root) ?? throw new ArgumentException("Snapshot root requires a parent.", nameof(root));
        if (!Directory.Exists(parent))
            throw new DirectoryNotFoundException("Provision the snapshot root's parent before startup.");
        EnsurePrivateDirectory(this.root);
        NativeDirectorySync.Flush(parent);
        var leasePath = Path.Combine(this.root, ".writer.lock");
        RejectLink(leasePath);
        writerLease = new FileStream(leasePath, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
    }

    public async ValueTask ActivateAsync(ZoneSnapshot snapshot, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        await EnterOperationAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(snapshot.ZoneId, cancellationToken).ConfigureAwait(false);
            if (current is not null)
            {
                if (current.Revision == snapshot.Revision && current.Serial == snapshot.Serial && current.Origin.Equals(snapshot.Origin) && string.Equals(current.ContentHash, snapshot.ContentHash, StringComparison.Ordinal))
                    return;
                if (snapshot.Revision <= current.Revision || !SoaSerial.IsNewer(snapshot.Serial, current.Serial) || !current.Origin.Equals(snapshot.Origin))
                    throw new InvalidOperationException("Snapshot activation must preserve origin and advance revision and serial.");
            }

            var directory = ZoneDirectory(snapshot.ZoneId);
            EnsurePrivateDirectory(directory);
            NativeDirectorySync.Flush(root);
            var document = new SnapshotDocument(1, snapshot.ZoneId, snapshot.Origin.ToString(), snapshot.Revision, snapshot.Serial, snapshot.GetPayload());
            var bytes = JsonSerializer.SerializeToUtf8Bytes(document, SnapshotJsonContext.Default.SnapshotDocument);
            var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            var bundlePath = BundlePath(directory, snapshot.Revision, hash);
            await WriteAtomicAsync(bundlePath, bytes, cancellationToken).ConfigureAwait(false);
            if (current is not null)
            {
                var active = await ReadDocumentAsync(Path.Combine(directory, "active.json"), SnapshotJsonContext.Default.ActiveDocument, cancellationToken).ConfigureAwait(false);
                await WriteAtomicAsync(Path.Combine(directory, "previous.json"), JsonSerializer.SerializeToUtf8Bytes(active, SnapshotJsonContext.Default.ActiveDocument), cancellationToken).ConfigureAwait(false);
            }

            var pointer = new ActiveDocument(1, snapshot.ZoneId, snapshot.Revision, hash);
            if (beforeActivePointerWrite is not null)
                await beforeActivePointerWrite(cancellationToken).ConfigureAwait(false);
            await WriteAtomicAsync(Path.Combine(directory, "active.json"), JsonSerializer.SerializeToUtf8Bytes(pointer, SnapshotJsonContext.Default.ActiveDocument), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            FinishOperation(releaseGate: true);
        }
    }

    public async ValueTask<ZoneSnapshot?> ReadActiveAsync(Guid zoneId, CancellationToken cancellationToken)
    {
        await EnterOperationAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReadCoreAsync(zoneId, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            FinishOperation(releaseGate: true);
        }
    }

    public async ValueTask<uint> CountActiveAsync(CancellationToken cancellationToken)
    {
        await EnterOperationAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            uint count = 0;
            foreach (var directory in Directory.EnumerateDirectories(root))
            {
                cancellationToken.ThrowIfCancellationRequested();
                RejectLink(directory);
                if (!Guid.TryParseExact(Path.GetFileName(directory), "N", out var zoneId))
                    throw new InvalidDataException("Unknown directory in the snapshot store.");
                if (await ReadCoreAsync(zoneId, cancellationToken).ConfigureAwait(false) is not null)
                    count = checked(count + 1);
            }
            return count;
        }
        finally
        {
            FinishOperation(releaseGate: true);
        }
    }

    /// <summary>Closes admission immediately; running operations retain the writer lease until they finish.</summary>
    /// <remarks>Use <see cref="DisposeAsync"/> to await the drain and release of all resources.</remarks>
    public void Dispose()
    {
        lock (lifetimeLock)
        {
            if (disposeRequested)
                return;
            disposeRequested = true;
        }
        try
        {
            admissionClosed.Cancel();
        }
        finally
        {
            lock (lifetimeLock)
            {
                admissionSignaled = true;
                if (operations == 0)
                    ReleaseResources();
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return new ValueTask(disposalCompleted.Task);
    }

    private async ValueTask EnterOperationAsync(CancellationToken cancellationToken)
    {
        lock (lifetimeLock)
        {
            ObjectDisposedException.ThrowIf(disposeRequested, this);
            operations = checked(operations + 1);
        }
        var acquired = false;
        try
        {
            using var admission = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, admissionClosed.Token);
            try
            {
                await gate.WaitAsync(admission.Token).ConfigureAwait(false);
                acquired = true;
            }
            catch (OperationCanceledException exception) when (admissionClosed.IsCancellationRequested)
            {
                throw new ObjectDisposedException("The snapshot store closed admission during shutdown.", exception);
            }
            lock (lifetimeLock)
                ObjectDisposedException.ThrowIf(disposeRequested, this);
        }
        catch
        {
            FinishOperation(acquired);
            throw;
        }
    }

    private void FinishOperation(bool releaseGate)
    {
        if (releaseGate)
            gate.Release();
        lock (lifetimeLock)
        {
            operations--;
            if (disposeRequested && admissionSignaled && operations == 0)
                ReleaseResources();
        }
    }

    private void ReleaseResources()
    {
        try
        {
            writerLease.Dispose();
            gate.Dispose();
            admissionClosed.Dispose();
            disposalCompleted.SetResult();
        }
        catch (Exception exception)
        {
            disposalCompleted.TrySetException(exception);
            throw;
        }
    }

    private async ValueTask<ZoneSnapshot?> ReadCoreAsync(Guid zoneId, CancellationToken cancellationToken)
    {
        var directory = ZoneDirectory(zoneId);
        RejectLink(directory);
        var activePath = Path.Combine(directory, "active.json");
        RejectLink(activePath);
        try
        {
            ActiveDocument pointer;
            try
            {
                pointer = await ReadDocumentAsync(activePath, SnapshotJsonContext.Default.ActiveDocument, cancellationToken).ConfigureAwait(false);
            }
            catch (FileNotFoundException)
            {
                EnsureUnpublishedDirectory(directory);
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                EnsureUnpublishedDirectory(directory);
                return null;
            }
            if (pointer.FormatVersion != 1 || pointer.ZoneId != zoneId || pointer.Revision <= 0 || pointer.Hash is null || pointer.Hash.Length != 64 || !IsLowerHex(pointer.Hash))
                throw new InvalidDataException("Invalid active snapshot pointer.");
            var path = BundlePath(directory, pointer.Revision, pointer.Hash);
            RejectLink(path);
            var bytes = await ReadBoundedBytesAsync(path, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(pointer.Hash, Convert.ToHexStringLower(SHA256.HashData(bytes)), StringComparison.Ordinal))
                throw new InvalidDataException("Snapshot integrity check failed.");
            var document = JsonSerializer.Deserialize(bytes, SnapshotJsonContext.Default.SnapshotDocument)
                ?? throw new InvalidDataException("Empty snapshot document.");
            if (document.FormatVersion != 1 || document.ZoneId != zoneId || document.Revision != pointer.Revision || document.Payload is null)
                throw new InvalidDataException("Snapshot identity or format mismatch.");
            return new ZoneSnapshot(document.ZoneId, DnsName.Parse(document.Origin), document.Revision, document.Serial, document.Payload);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Invalid snapshot encoding.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("Invalid snapshot metadata.", exception);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("Invalid snapshot origin.", exception);
        }
    }

    private static void EnsureUnpublishedDirectory(string directory)
    {
        try
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                RejectLink(entry);
                var name = Path.GetFileName(entry);
                if (!name.EndsWith(".tmp", StringComparison.Ordinal) || !Guid.TryParseExact(name.AsSpan(0, name.Length - 4), "N", out _) || (File.GetAttributes(entry) & FileAttributes.Directory) != default(FileAttributes))
                    throw new InvalidDataException("Active metadata is missing while published or unknown state remains; verified reconciliation is required.");
            }
        }
        catch (DirectoryNotFoundException)
        {
            // A zone with no directory has no local publication evidence.
        }
    }

    private static async ValueTask<T> ReadDocumentAsync<T>(string path, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize(bytes, type) ?? throw new InvalidDataException("Empty snapshot pointer.");
    }

    private static async ValueTask<byte[]> ReadBoundedBytesAsync(string path, CancellationToken cancellationToken)
    {
        RejectLink(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        if (stream.Length is <= 0 or > MaximumDocumentBytes)
            throw new InvalidDataException("Snapshot document exceeds its size bound.");
        var bytes = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.ReadByte() != -1)
            throw new InvalidDataException("Snapshot changed while reading.");
        return bytes;
    }

    private static async ValueTask WriteAtomicAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        if (bytes.Length > MaximumDocumentBytes)
            throw new InvalidDataException("Snapshot document exceeds its size bound.");
        var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Snapshot path requires a directory.");
        var temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.WriteThrough,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                FlushToDisk(stream);
            }
            cancellationToken.ThrowIfCancellationRequested();
            RejectLink(path);
            File.Move(temporary, path, overwrite: true);
            NativeDirectorySync.Flush(directory);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    private string ZoneDirectory(Guid zoneId)
    {
        if (zoneId == Guid.Empty)
            throw new ArgumentException("Zone identity cannot be empty.", nameof(zoneId));
        return Path.Combine(root, zoneId.ToString("N"));
    }

    // FlushAsync drains managed buffers but provides no flush-to-disk parameter.
    // This bounded publication path needs fsync before its atomic pointer switch.
    private static void FlushToDisk(FileStream stream) => stream.Flush(flushToDisk: true);

    private static string BundlePath(string directory, long revision, string hash) => Path.Combine(directory, FormattableString.Invariant($"{revision}-{hash}.json"));

    private static bool IsLowerHex(string value)
    {
        foreach (var character in value)
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
                return false;
        return true;
    }

    private static void EnsurePrivateDirectory(string path)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        RejectLink(path);
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != UnixFileMode.None)
            throw new IOException("Snapshot directories must be private to the service account.");
    }

    private static void RejectLink(string path)
    {
        if (new FileInfo(path).LinkTarget is not null || ((File.Exists(path) || Directory.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != default(FileAttributes)))
            throw new IOException("Symbolic links are not allowed in snapshot storage.");
    }
}
