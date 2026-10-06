using System.Runtime.InteropServices;

namespace Mk8.Dns.Configuration;

internal static partial class PrivateInputType
{
    internal static void RequireRegularFile(string path)
    {
        if (Statx(-100, path, 0x100, 1, out var status) != 0 || (status.Mask & 1) == 0 || (status.Mode & 0xF000) != 0x8000)
            throw new IOException("Private input requires a regular file without a symbolic link.");
    }

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Statx(int directory, string path, int flags, uint mask, out Status status);

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Status
    {
        [FieldOffset(0)]
        public uint Mask;
        [FieldOffset(28)]
        public ushort Mode;
    }
}
