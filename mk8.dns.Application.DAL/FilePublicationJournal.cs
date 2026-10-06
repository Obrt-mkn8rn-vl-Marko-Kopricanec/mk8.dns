using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.DAL;

public sealed class FilePublicationJournal : IPublicationJournal, IDisposable
{
    public const int MaximumEntries = 4096;
    private readonly string root;
    private readonly FileStream lease;
    private readonly Lock sync = new();
    private bool disposed;

    public FilePublicationJournal(string directory)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        if (!OperatingSystem.IsLinux() || !Path.IsPathFullyQualified(directory))
            throw new ArgumentException("Publication storage requires an absolute Linux directory.", nameof(directory));
        root = Path.GetFullPath(directory);
        var parent = Path.GetDirectoryName(root) ?? throw new ArgumentException("A stable parent is required.", nameof(directory));
        NativeStoragePath.RequireDirectory(parent);
        if (!NativeStoragePath.IsDirectoryPresent(root))
        {
            Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            NativeDirectorySync.Flush(parent);
        }
        NativeStoragePath.RequireDirectory(root);
        File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var lockPath = Path.Combine(root, ".writer.lock");
        // Existing links and wrong-kind entries are rejected before the exclusive lease is opened.
        if (Directory.EnumerateFileSystemEntries(root).Contains(lockPath, StringComparer.Ordinal))
            NativeStoragePath.RequireRegularFile(lockPath);
        lease = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            File.SetUnixFileMode(lockPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            InspectEntries();
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    public ValueTask SaveAsync(string id, ReadOnlyMemory<byte> body, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateId(id);
        if (body.Length is < 1 or > ZoneSnapshot.MaximumPayloadBytes + 512 || signature.Length != 64 || !string.Equals(id, Convert.ToHexStringLower(SHA256.HashData(body.Span)), StringComparison.Ordinal))
            throw new ArgumentException("Invalid publication journal entry.", nameof(body));
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            InspectEntries();
            var path = Path.Combine(root, id + ".pub");
            if (Directory.EnumerateFileSystemEntries(root).Contains(path, StringComparer.Ordinal))
            {
                var existing = ReadCore(id);
                if (!existing.Body.Span.SequenceEqual(body.Span))
                    throw new InvalidDataException("Publication identity already identifies different contents.");
                NativeDirectorySync.Flush(root);
                return ValueTask.CompletedTask;
            }
            if (Directory.EnumerateFiles(root, "*.pub").Count() >= MaximumEntries)
                throw new IOException("Publication retention capacity requires explicit maintenance.");
            var temporary = Path.Combine(root, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var file = CreatePrivateFile(temporary))
                {
                    Span<byte> length = stackalloc byte[4];
                    BinaryPrimitives.WriteInt32LittleEndian(length, body.Length);
                    file.Write(length);
                    file.Write(body.Span);
                    file.Write(signature.Span);
                    FlushDurably(file);
                }
                File.Move(temporary, path, overwrite: false);
                NativeDirectorySync.Flush(root);
            }
            finally
            {
                if (File.Exists(temporary))
                    File.Delete(temporary);
            }
            return ValueTask.CompletedTask;
        }
    }

    public ValueTask<PublicationRequest> ReadAsync(string id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateId(id);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            InspectEntries();
            return ValueTask.FromResult(ReadCore(id));
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed)
                return;
            disposed = true;
            lease.Dispose();
        }
    }

    public ValueTask RecordActivationAsync(string id, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateId(id);
        if (signature.Length != 64)
            throw new ArgumentException("An activation signature is required.", nameof(signature));
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            InspectEntries();
            _ = ReadCore(id);
            var destination = Path.Combine(root, id + ".act");
            if (Directory.EnumerateFileSystemEntries(root).Contains(destination, StringComparer.Ordinal))
            {
                NativeStoragePath.RequireRegularFile(destination);
                if (new FileInfo(destination).Length != 64)
                    throw new InvalidDataException("Invalid durable activation receipt.");
                NativeDirectorySync.Flush(root);
                return ValueTask.CompletedTask;
            }
            var temporary = Path.Combine(root, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var file = CreatePrivateFile(temporary))
                {
                    file.Write(signature.Span);
                    FlushDurably(file);
                }
                File.Move(temporary, destination, overwrite: false);
                NativeDirectorySync.Flush(root);
            }
            finally
            {
                if (File.Exists(temporary))
                    File.Delete(temporary);
            }
            return ValueTask.CompletedTask;
        }
    }

    public ValueTask<IReadOnlyList<string>> ReadActivatedIdsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            InspectEntries();
            IReadOnlyList<string> ids = Directory.EnumerateFiles(root, "*.act").Select(path => Path.GetFileName(path)[..64]).ToArray();
            return ValueTask.FromResult(ids);
        }
    }

    public ValueTask<byte[]> ReadActivationSignatureAsync(string id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateId(id);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            InspectEntries();
            var path = Path.Combine(root, id + ".act");
            NativeStoragePath.RequireRegularFile(path);
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length != 64)
                throw new InvalidDataException("Invalid durable activation receipt.");
            var signature = new byte[64];
            file.ReadExactly(signature);
            return ValueTask.FromResult(signature);
        }
    }

    private PublicationRequest ReadCore(string id)
    {
        var path = Path.Combine(root, id + ".pub");
        NativeStoragePath.RequireRegularFile(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 69 or > ZoneSnapshot.MaximumPayloadBytes + 580)
            throw new InvalidDataException("Invalid publication proof size.");
        Span<byte> length = stackalloc byte[4];
        file.ReadExactly(length);
        var count = BinaryPrimitives.ReadInt32LittleEndian(length);
        if (count is < 1 or > ZoneSnapshot.MaximumPayloadBytes + 512 || file.Length != count + 68)
            throw new InvalidDataException("Invalid publication proof bounds.");
        var body = new byte[count];
        var signature = new byte[64];
        file.ReadExactly(body);
        file.ReadExactly(signature);
        if (!string.Equals(id, Convert.ToHexStringLower(SHA256.HashData(body)), StringComparison.Ordinal))
            throw new InvalidDataException("Publication proof digest differs from its identity.");
        return new PublicationRequest("prepare", body, signature, id);
    }

    private void InspectEntries()
    {
        NativeStoragePath.RequireDirectory(root);
        foreach (var entry in Directory.EnumerateFileSystemEntries(root))
        {
            NativeStoragePath.RequireRegularFile(entry);
            var name = Path.GetFileName(entry);
            if (string.Equals(name, ".writer.lock", StringComparison.Ordinal))
                continue;
            if (name.Length == 68 && (name.EndsWith(".pub", StringComparison.Ordinal) || name.EndsWith(".act", StringComparison.Ordinal)))
                ValidateId(name[..64]);
            else if (name.Length != 36 || !name.EndsWith(".tmp", StringComparison.Ordinal) || !Guid.TryParseExact(name[..32], "N", out _))
                throw new InvalidDataException("Unexpected publication storage entry.");
        }
    }

    private static FileStream CreatePrivateFile(string path)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        return new FileStream(path, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite });
    }

    private static void FlushDurably(FileStream file) => file.Flush(flushToDisk: true);

    private static void ValidateId(string id)
    {
        if (id is not { Length: 64 } || id.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException("A canonical SHA-256 publication identity is required.", nameof(id));
    }
}
