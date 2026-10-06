namespace Mk8.Dns.UnitTests;

internal sealed class TemporaryDirectory : IDisposable
{
    internal TemporaryDirectory()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Filesystem and host foundation tests require Linux.");
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "m8dns-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    internal string Path { get; }

    public void Dispose() => Directory.Delete(Path, recursive: true);
}
