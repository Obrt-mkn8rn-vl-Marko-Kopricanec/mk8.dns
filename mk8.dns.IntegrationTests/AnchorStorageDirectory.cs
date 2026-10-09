namespace Mk8.Dns.IntegrationTests;

internal sealed class AnchorStorageDirectory : IDisposable
{
    internal AnchorStorageDirectory()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "m8-anchor-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    internal string Path { get; }
    public void Dispose() => Directory.Delete(Path, recursive: true);
}
