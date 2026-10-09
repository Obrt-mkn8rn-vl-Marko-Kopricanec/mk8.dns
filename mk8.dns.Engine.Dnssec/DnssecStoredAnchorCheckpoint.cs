using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed class DnssecStoredAnchorCheckpoint
{
    private readonly byte[] checkpoint;

    public DnssecStoredAnchorCheckpoint(DnsName origin, long revision, ReadOnlySpan<byte> checkpoint)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentOutOfRangeException.ThrowIfLessThan(revision, 1);
        if (checkpoint.Length is < 49 or > DnssecTrustAnchorTracker.MaximumCheckpointBytes)
            throw new FormatException("Invalid stored anchor checkpoint size.");
        this.checkpoint = checkpoint.ToArray();
        // Validate the owned bytes, never offsets into mutable caller storage.
        _ = DnssecAnchorCheckpoint.Decode(origin, this.checkpoint);
        Origin = origin;
        Revision = revision;
    }

    public DnsName Origin { get; }
    public long Revision { get; }
    public byte[] GetCheckpoint() => (byte[])checkpoint.Clone();
}
