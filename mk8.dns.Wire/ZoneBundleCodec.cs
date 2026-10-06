using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public static class ZoneBundleCodec
{
    private static ReadOnlySpan<byte> Magic => "M8Z1"u8;

    public static ZoneSnapshot Compile(Guid zoneId, long revision, AuthoritativeZone zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        using var output = new MemoryStream();
        output.Write(Magic);
        var records = zone.GetAllRecords();
        Span<byte> metadata = stackalloc byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(metadata, (ushort)records.Count);
        output.Write(metadata[..2]);
        foreach (var record in records.OrderBy(record => record.Owner.ToString(), StringComparer.Ordinal).ThenBy(record => record.Type).ThenBy(record => Convert.ToHexString(record.GetData()), StringComparer.Ordinal))
        {
            output.Write(record.GetOwnerWire());
            BinaryPrimitives.WriteUInt16BigEndian(metadata, record.Type);
            BinaryPrimitives.WriteUInt32BigEndian(metadata[2..], record.Ttl);
            var data = record.GetData();
            BinaryPrimitives.WriteUInt16BigEndian(metadata[6..], (ushort)data.Length);
            output.Write(metadata);
            output.Write(data);
        }
        return new ZoneSnapshot(zoneId, zone.Origin, revision, zone.Soa.GetSoaSerial(), output.ToArray());
    }

    public static AuthoritativeZone Decode(ZoneSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        try
        {
            return DecodeCore(snapshot);
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("Invalid authoritative zone metadata or records.", exception);
        }
    }

    private static AuthoritativeZone DecodeCore(ZoneSnapshot snapshot)
    {
        var payload = snapshot.GetPayload().AsSpan();
        Require(payload.Length >= 6 && payload[..4].SequenceEqual(Magic));
        var count = BinaryPrimitives.ReadUInt16BigEndian(payload[4..]);
        Require(count is >= 1 and <= 10_000);
        var offset = 6;
        var records = new List<DnsRecord>(count);
        for (var index = 0; index < count; index++)
        {
            var start = offset;
            while (true)
            {
                Require(offset < payload.Length);
                var length = payload[offset++];
                Require(length <= 63 && length <= payload.Length - offset);
                offset += length;
                if (length == 0)
                    break;
            }
            var name = payload[start..offset];
            Require(offset + 8 <= payload.Length);
            var type = BinaryPrimitives.ReadUInt16BigEndian(payload[offset..]);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(payload[(offset + 2)..]);
            var lengthData = BinaryPrimitives.ReadUInt16BigEndian(payload[(offset + 6)..]);
            offset += 8;
            Require(lengthData <= payload.Length - offset);
            records.Add(new DnsRecord(name, type, ttl, payload.Slice(offset, lengthData)));
            offset += lengthData;
        }
        Require(offset == payload.Length);
        var zone = new AuthoritativeZone(snapshot.Origin, records);
        Require(zone.Soa.GetSoaSerial() == snapshot.Serial);
        return zone;
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Invalid versioned authoritative zone bundle.");
    }
}
