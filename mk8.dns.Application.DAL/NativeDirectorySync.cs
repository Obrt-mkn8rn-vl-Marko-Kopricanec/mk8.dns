using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Mk8.Dns.Application.DAL;

internal static partial class NativeDirectorySync
{
    internal static void Flush(string path)
    {
        var descriptor = Open(path, 0x10000 | 0x20000 | 0x80000); // O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC on Linux.
        if (descriptor < 0)
            throw new IOException("Unable to open the snapshot directory for durability.", new Win32Exception(Marshal.GetLastPInvokeError()));
        try
        {
            if (Sync(descriptor) != 0)
                throw new IOException("Unable to flush the snapshot directory.", new Win32Exception(Marshal.GetLastPInvokeError()));
        }
        finally
        {
            _ = Close(descriptor);
        }
    }

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Open(string path, int flags);

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Sync(int descriptor);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Close(int descriptor);
}
