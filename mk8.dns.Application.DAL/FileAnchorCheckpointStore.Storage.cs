using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Application.DAL;

public sealed partial class FileAnchorCheckpointStore
{
    private const UnixFileMode PrivateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const int ExclusiveNonBlocking = 2 | 4; // Linux LOCK_EX | LOCK_NB.

    private FileStream AcquireLease(bool create, Func<SafeFileHandle, int, int>? nativeLock)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux anchor storage is required.");
        var parent = Path.GetDirectoryName(root) ?? throw new IOException("A stable parent is required.");
        NativeStoragePath.RequireDirectory(parent);
        if (!NativeStoragePath.IsDirectoryPresent(root))
        {
            if (!create) throw new IOException("Anchor storage is absent.");
            Directory.CreateDirectory(root, PrivateDirectory); NativeDirectorySync.Flush(parent);
        }
        NativeStoragePath.RequireDirectory(root);
        if (File.GetUnixFileMode(root) != PrivateDirectory)
            throw new IOException("Anchor storage requires a private directory.");
        var path = Path.Combine(root, ".writer.lock");
        if (Directory.EnumerateFileSystemEntries(root).Contains(path, StringComparer.Ordinal) || !create)
            RequirePrivateFile(path);
        var options = new FileStreamOptions
        {
            Mode = create ? FileMode.OpenOrCreate : FileMode.Open,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
        };
        if (create) options.UnixCreateMode = PrivateFile;
        var stream = new FileStream(path, options);
        try
        {
            // FileShare.None is best-effort on Unix. Require an actual flock on this owned handle.
            var result = nativeLock is null ? Flock(stream.SafeFileHandle, ExclusiveNonBlocking)
                : nativeLock(stream.SafeFileHandle, ExclusiveNonBlocking);
            if (result != 0)
                throw new IOException("Unable to acquire the exclusive anchor storage lease.", new Win32Exception(Marshal.GetLastPInvokeError()));
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    [LibraryImport("libc", EntryPoint = "flock", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Flock(SafeFileHandle descriptor, int operation);

    private void Initialize(DnssecTrustAnchorTracker initial)
    {
        var entries = InspectEntries();
        if (lease.Length != 0 || entries.Generations.Count != 0 || entries.Pointer)
            throw new InvalidDataException("Previously initialized anchor storage cannot be bootstrapped.");
        tracker = initial;
        var checkpoint = initial.CreateCheckpoint();
        var marker = AnchorStoreEnvelope.Encode("M8L1", identity, origin, 0, [], [], authenticationKey);
        lease.Write(marker); lease.Flush(flushToDisk: true); NativeDirectorySync.Flush(root);
        Commit(checkpoint);
    }

    private void Commit(byte[] checkpoint)
    {
        var next = revision + 1;
        var generation = AnchorStoreEnvelope.Encode("M8S1", identity, origin, next, digest, checkpoint, authenticationKey);
        var nextDigest = SHA256.HashData(generation);
        try
        {
            Publish(generation, GenerationPath(next), overwrite: false, AnchorStoreWriteStage.GenerationFile, AnchorStoreWriteStage.GenerationDirectory);
            var pointer = AnchorStoreEnvelope.Encode("M8P1", identity, origin, next, nextDigest, [], authenticationKey);
            Publish(pointer, Path.Combine(root, "active.bin"), overwrite: true, AnchorStoreWriteStage.PointerFile, AnchorStoreWriteStage.PointerDirectory);
            revision = next; digest = nextDigest;
        }
        catch { faulted = true; throw; }
    }

    private void Publish(byte[] data, string destination, bool overwrite, AnchorStoreWriteStage fileStage, AnchorStoreWriteStage directoryStage)
    {
        NativeStoragePath.RequireDirectory(root);
        var temporary = Path.Combine(root, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var file = CreatePrivateFile(temporary))
            {
                file.Write(data); file.Flush(flushToDisk: true);
                afterDurableWrite?.Invoke(fileStage);
            }
            File.Move(temporary, destination, overwrite);
            NativeDirectorySync.Flush(root);
            afterDurableWrite?.Invoke(directoryStage);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private string GenerationPath(long number) => Path.Combine(root, number.ToString("x16", System.Globalization.CultureInfo.InvariantCulture) + ".anchor");

    private static void RequirePrivateFile(string path)
    {
        NativeStoragePath.RequireRegularFile(path);
        if (!OperatingSystem.IsLinux() || File.GetUnixFileMode(path) != PrivateFile)
            throw new IOException("Anchor storage requires a private regular file.");
    }

    private static FileStream CreatePrivateFile(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux anchor storage is required.");
        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = PrivateFile,
        });
    }

    private static byte[] ReadBounded(string path)
    {
        RequirePrivateFile(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 55 or > AnchorStoreEnvelope.MaximumBytes)
            throw new InvalidDataException("Invalid authenticated anchor file size.");
        var data = new byte[(int)file.Length]; file.ReadExactly(data);
        return data;
    }
}
