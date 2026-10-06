using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Mk8.Dns.Application.DAL;

internal static partial class NativeStoragePath
{
    private const int DirectoryType = 0x4000;
    private const int RegularFileType = 0x8000;
    private const int TypeMask = 0xF000;

    internal static bool IsDirectoryPresent(string path)
    {
        var type = ReadType(path);
        if (type is null)
            return false;
        if (type != DirectoryType)
            throw new IOException("Snapshot storage requires a directory at this path.");
        return true;
    }

    internal static void RequireDirectory(string path)
    {
        if (!IsDirectoryPresent(path))
            throw new IOException("A required snapshot directory is missing.");
    }

    internal static void RequireRegularFile(string path)
    {
        if (ReadType(path) != RegularFileType)
            throw new IOException("Snapshot storage requires a regular file at this path.");
    }

    private static int? ReadType(string path)
    {
        // AT_FDCWD, AT_SYMLINK_NOFOLLOW, STATX_TYPE: do not resolve a link at the inspected path.
        if (Statx(-100, path, 0x100, 1, out var status) == 0)
        {
            if ((status.Mask & 1) == 0)
                throw new IOException("Snapshot storage object type is unavailable.");
            return status.Mode & TypeMask;
        }
        var error = Marshal.GetLastPInvokeError();
        if (error == 2) // ENOENT only. ENOTDIR and access errors must remain failures.
            return null;
        throw new IOException("Unable to inspect the snapshot storage path.", new Win32Exception(error));
    }

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Statx(int directory, string path, int flags, uint mask, out StatxBuffer status);

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct StatxBuffer
    {
        [FieldOffset(0)]
        public uint Mask;

        [FieldOffset(28)]
        public ushort Mode;
    }
}
