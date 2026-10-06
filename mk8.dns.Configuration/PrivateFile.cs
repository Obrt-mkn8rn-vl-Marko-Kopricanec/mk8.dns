namespace Mk8.Dns.Configuration;

public static class PrivateFile
{
    public static byte[] Read(string path, int maximumBytes)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        if (!OperatingSystem.IsLinux() || !Path.IsPathFullyQualified(path))
            throw new ArgumentException("Private inputs require an absolute Linux path.", nameof(path));
        PrivateInputType.RequireRegularFile(path);
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != (FileAttributes)0
            || (File.GetUnixFileMode(path) & ~(UnixFileMode.UserRead | UnixFileMode.UserWrite)) != UnixFileMode.None || info.Length > maximumBytes)
            throw new IOException("Private input must be a bounded owner-only regular file.");
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > maximumBytes)
            throw new IOException("Private input exceeds its size bound.");
        var bytes = new byte[checked((int)input.Length)];
        input.ReadExactly(bytes);
        return bytes;
    }
}
