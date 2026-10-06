using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Mk8.Dns.Transport;

public sealed partial class PrivateUnixSocket : IDisposable
{
    private readonly FileStream lease;
    private bool disposed;

    public PrivateUnixSocket(string path)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        ValidatePath(path);
        Path = path;
        var directory = System.IO.Path.GetDirectoryName(path) ?? throw new ArgumentException("Socket requires a parent directory.", nameof(path));
        EnsurePrivateDirectory(directory);
        var leasePath = path + ".lock";
        if (new FileInfo(leasePath).LinkTarget is not null)
            throw new IOException("Socket leases cannot be symbolic links.");
        lease = new FileStream(leasePath, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
        try
        {
            var result = Stat(path, out var status);
            if (result == 0)
            {
                if ((status.Mode & 0xF000) != 0xC000)
                    throw new IOException("An existing socket path is not a Unix socket.");
                File.Delete(path);
            }
            else if (Marshal.GetLastPInvokeError() != 2)
            {
                throw new IOException("Cannot inspect the Unix socket path.", new Win32Exception(Marshal.GetLastPInvokeError()));
            }
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    public string Path { get; }

    public void SetSocketPermissions()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite);
    }

    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;
        lease.Dispose();
    }

    internal static void ValidatePath(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Private local IPC currently requires Linux.");
        if (!System.IO.Path.IsPathFullyQualified(path) || Encoding.UTF8.GetByteCount(path) > 100)
            throw new ArgumentException("Use an absolute Unix socket path of at most 100 UTF-8 bytes.", nameof(path));
    }

    private static void EnsurePrivateDirectory(string directory)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        if (new DirectoryInfo(directory).LinkTarget is not null)
            throw new IOException("The runtime directory cannot be a symbolic link.");
        Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var unsafeMode = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((File.GetUnixFileMode(directory) & unsafeMode) != UnixFileMode.None)
            throw new IOException("Runtime directory must be private; an operator-controlled group may have traverse access only.");
    }

    private static int Stat(string path, out StatxBuffer status) => Statx(-100, path, 0x100, 1, out status); // AT_FDCWD, AT_SYMLINK_NOFOLLOW, STATX_TYPE.

    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int Statx(int directory, string path, int flags, uint mask, out StatxBuffer status);

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct StatxBuffer
    {
        [FieldOffset(28)]
        public ushort Mode;
    }
}
