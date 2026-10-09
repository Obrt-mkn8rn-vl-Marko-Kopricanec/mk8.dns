using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.UnitTests;

internal sealed class AnchorStorageFixture : IDisposable
{
    private readonly TemporaryDirectory directory = new();
    internal TrustAnchorFixture Keys { get; } = new();
    internal byte[] Secret { get; } = RandomNumberGenerator.GetBytes(32);
    internal Guid Identity { get; } = Guid.NewGuid();
    internal string Root => Path.Combine(directory.Path, "anchors");
    internal string Head => Path.Combine(Root, "active.bin");
    internal string Marker => Path.Combine(Root, ".writer.lock");
    internal string Generation(long revision) => Path.Combine(Root, revision.ToString("x16", System.Globalization.CultureInfo.InvariantCulture) + ".anchor");
    internal FileAnchorCheckpointStore Create(DnssecTrustAnchorTracker? tracker = null)
        => FileAnchorCheckpointStore.Create(Root, Identity, tracker ?? Keys.Tracker(Keys.A), Secret);
    internal FileAnchorCheckpointStore Open(long floor = 1)
        => FileAnchorCheckpointStore.Open(Root, Identity, Keys.Origin, Secret, floor, DnssecFixture.Verifier, Keys.Clock);
    internal Dictionary<string, string> Image() => Directory.EnumerateFiles(Root)
        .Where(path => !string.Equals(Path.GetFileName(path), ".writer.lock", StringComparison.Ordinal))
        .ToDictionary(path => Path.GetFileName(path), path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))), StringComparer.Ordinal);
    internal static void Write(string path, byte[] data)
    {
        File.WriteAllBytes(path, data);
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    internal byte[] Seal(byte[] body) => [.. body, .. HMACSHA256.HashData(Secret, body)];
    public void Dispose() { Keys.Dispose(); directory.Dispose(); CryptographicOperations.ZeroMemory(Secret); }
}
