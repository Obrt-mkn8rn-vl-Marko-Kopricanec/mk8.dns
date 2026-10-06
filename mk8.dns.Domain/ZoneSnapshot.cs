using System.Security.Cryptography;

namespace Mk8.Dns.Domain;

public sealed class ZoneSnapshot
{
    public const int MaximumPayloadBytes = 1_048_576;
    private readonly byte[] payload;

    public ZoneSnapshot(Guid zoneId, DnsName origin, long revision, uint serial, ReadOnlySpan<byte> payload)
    {
        if (zoneId == Guid.Empty)
            throw new ArgumentException("Zone identity cannot be empty.", nameof(zoneId));
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(revision);
        if (payload.IsEmpty || payload.Length > MaximumPayloadBytes)
            throw new ArgumentOutOfRangeException(nameof(payload));
        ZoneId = zoneId;
        Origin = origin;
        Revision = revision;
        Serial = serial;
        this.payload = payload.ToArray();
        ContentHash = Convert.ToHexStringLower(SHA256.HashData(this.payload));
    }

    public Guid ZoneId { get; }
    public DnsName Origin { get; }
    public long Revision { get; }
    public uint Serial { get; }
    public string ContentHash { get; }
    public byte[] GetPayload() => (byte[])payload.Clone();
}
