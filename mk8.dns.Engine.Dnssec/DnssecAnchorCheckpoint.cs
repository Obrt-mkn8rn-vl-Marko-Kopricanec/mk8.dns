using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

internal static class DnssecAnchorCheckpoint
{
    internal sealed record Sponsor(byte Index, bool EarlyRevocation);
    internal sealed record Entry(DnsRecord Key, DnssecAnchorState State, long RemainingTicks, Sponsor[] Sponsors);
    internal sealed record Snapshot(long Seconds, Entry[] Entries);

    // M8A1 uses little-endian fixed-width integers, canonical wire names and
    // lexicographically sorted DNSKEY RDATA. The final 32 bytes are SHA-256.
    internal static byte[] Encode(DnsName origin, long seconds, Entry[] entries)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write("M8A1"u8);
            var name = origin.ToWire();
            writer.Write((ushort)name.Length);
            writer.Write(name);
            writer.Write(seconds);
            writer.Write((byte)entries.Length);
            foreach (var entry in entries)
            {
                writer.Write((byte)entry.State);
                var key = entry.Key.GetData();
                writer.Write(checked((ushort)key.Length));
                writer.Write(key);
                if (entry.State != DnssecAnchorState.AddPending)
                    continue;
                writer.Write(entry.RemainingTicks);
                writer.Write((byte)entry.Sponsors.Length);
                foreach (var sponsor in entry.Sponsors)
                {
                    writer.Write(sponsor.Index);
                    writer.Write(sponsor.EarlyRevocation ? (byte)1 : (byte)0);
                }
            }
        }
        if (stream.Length + 32 > DnssecTrustAnchorTracker.MaximumCheckpointBytes)
            throw new InvalidOperationException("Anchor checkpoint exceeds its bound.");
        var body = stream.ToArray();
        return [.. body, .. SHA256.HashData(body)];
    }

    internal static Snapshot Decode(DnsName expectedOrigin, ReadOnlySpan<byte> input)
    {
        if (input.Length is < 49 or > DnssecTrustAnchorTracker.MaximumCheckpointBytes)
            throw new FormatException("Invalid anchor checkpoint size.");
        var owned = input.ToArray();
        var body = owned.AsSpan(0, owned.Length - 32);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(body), owned.AsSpan(owned.Length - 32)))
            throw new FormatException("Anchor checkpoint checksum mismatch.");
        try
        {
            using var stream = new MemoryStream(body.ToArray(), writable: false);
            using var reader = new BinaryReader(stream);
            if (!reader.ReadBytes(4).AsSpan().SequenceEqual("M8A1"u8))
                throw new FormatException("Unsupported anchor checkpoint version.");
            var wire = ReadBytes(reader, reader.ReadUInt16());
            var origin = DnsName.FromWire(wire);
            if (!origin.Equals(expectedOrigin) || !origin.ToWire().AsSpan().SequenceEqual(wire) || DnssecData.IsWildcard(origin))
                throw new FormatException("Anchor checkpoint origin mismatch.");
            var seconds = reader.ReadInt64();
            _ = DateTimeOffset.FromUnixTimeSeconds(seconds);
            var count = reader.ReadByte();
            if (count is 0 or > DnssecTrustAnchorTracker.MaximumTrackedKeys)
                throw new FormatException("Invalid anchor checkpoint key count.");
            var entries = ReadEntries(reader, origin, count);
            if (stream.Position != stream.Length)
                throw new FormatException("Trailing checkpoint data.");
            foreach (var entry in entries)
                if (entry.Sponsors.Any(sponsor => entries[sponsor.Index].State == DnssecAnchorState.AddPending
                        || sponsor.EarlyRevocation && entries[sponsor.Index].State != DnssecAnchorState.Revoked)
                    || entry.State == DnssecAnchorState.AddPending && entry.Sponsors.All(sponsor => sponsor.EarlyRevocation))
                    throw new FormatException("Inconsistent checkpoint sponsor history.");
            return new Snapshot(seconds, entries);
        }
        catch (Exception error) when (error is EndOfStreamException or ArgumentException)
        {
            throw new FormatException("Malformed anchor checkpoint.", error);
        }
    }

    private static Entry[] ReadEntries(BinaryReader reader, DnsName origin, byte count)
    {
        var entries = new Entry[count];
        string? previous = null;
        for (var index = 0; index < count; index++)
        {
            var state = (DnssecAnchorState)reader.ReadByte();
            if (state is < DnssecAnchorState.AddPending or > DnssecAnchorState.Revoked)
                throw new FormatException("Invalid anchor checkpoint state.");
            var key = new DnsRecord(origin, 48, 0, ReadBytes(reader, reader.ReadUInt16()));
            if (!DnssecAnchorProof.TryKey(key, revoked: false, out var data))
                throw new FormatException("Invalid anchor checkpoint SEP key.");
            var identity = DnssecAnchorProof.Identity(data);
            if (previous is not null && StringComparer.Ordinal.Compare(previous, identity) >= 0)
                throw new FormatException("Checkpoint keys must be unique and canonically ordered.");
            previous = identity;
            long remaining = 0;
            Sponsor[] sponsors = [];
            if (state == DnssecAnchorState.AddPending)
            {
                remaining = reader.ReadInt64();
                if (remaining < 0 || remaining > (long)uint.MaxValue * TimeSpan.TicksPerSecond)
                    throw new FormatException("Invalid anchor hold-down duration.");
                var length = reader.ReadByte();
                if (length == 0 || length > count)
                    throw new FormatException("Invalid anchor sponsor count.");
                sponsors = new Sponsor[length];
                for (var sponsor = 0; sponsor < length; sponsor++)
                {
                    var target = reader.ReadByte();
                    var early = reader.ReadByte();
                    if (target >= count || target == index || early > 1 || sponsor > 0 && target <= sponsors[sponsor - 1].Index)
                        throw new FormatException("Invalid anchor sponsor reference.");
                    sponsors[sponsor] = new Sponsor(target, early == 1);
                }
            }
            entries[index] = new Entry(key, state, remaining, sponsors);
        }
        return entries;
    }

    private static byte[] ReadBytes(BinaryReader reader, int length)
    {
        if (length == 0 || length > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new FormatException("Invalid checkpoint field length.");
        return reader.ReadBytes(length);
    }
}
