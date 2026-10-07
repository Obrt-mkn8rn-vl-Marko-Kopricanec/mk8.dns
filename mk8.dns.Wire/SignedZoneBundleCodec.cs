using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public static class SignedZoneBundleCodec
{
    private static ReadOnlySpan<byte> Magic => "M8Z2"u8;

    public static ZoneSnapshot Compile(Guid zoneId, long revision, ZoneContents contents)
    {
        ArgumentNullException.ThrowIfNull(contents);
        if (!contents.IsSigned)
            return ZoneBundleCodec.Compile(zoneId, revision, contents.Source);
        using var output = new MemoryStream();
        output.Write(Magic);
        var records = contents.GetAllRecords();
        Span<byte> metadata = stackalloc byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(metadata, (ushort)records.Count);
        output.Write(metadata[..2]);
        foreach (var record in records.OrderBy(record => record.Owner.ToString(), StringComparer.Ordinal).ThenBy(record => record.Type)
            .ThenBy(record => Convert.ToHexString(record.GetData()), StringComparer.Ordinal))
        {
            output.Write(record.GetOwnerWire());
            BinaryPrimitives.WriteUInt16BigEndian(metadata, record.Type);
            BinaryPrimitives.WriteUInt32BigEndian(metadata[2..], record.Ttl);
            var data = record.GetData();
            BinaryPrimitives.WriteUInt16BigEndian(metadata[6..], (ushort)data.Length);
            output.Write(metadata);
            output.Write(data);
        }
        return new ZoneSnapshot(zoneId, contents.Source.Origin, revision, contents.Source.Soa.GetSoaSerial(), output.ToArray());
    }

    public static ZoneContents Decode(ZoneSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var payload = snapshot.GetPayload().AsSpan();
        if (payload.Length >= 4 && payload[..4].SequenceEqual("M8Z1"u8))
            return new ZoneContents(ZoneBundleCodec.Decode(snapshot));
        try
        {
            Require(payload.Length >= 6 && payload[..4].SequenceEqual(Magic));
            var count = BinaryPrimitives.ReadUInt16BigEndian(payload[4..]);
            Require(count is >= 1 and <= ZoneContents.MaximumRecords);
            var offset = 6;
            var records = new List<DnsRecord>(count);
            for (var index = 0; index < count; index++)
                records.Add(ReadRecord(payload, ref offset));
            Require(offset == payload.Length);
            var source = new AuthoritativeZone(snapshot.Origin, records.Where(record => record.Type is not (46 or 47 or 48)));
            Require(source.Soa.GetSoaSerial() == snapshot.Serial);
            var contents = new ZoneContents(source, records.Where(record => record.Type is 46 or 47 or 48));
            Require(contents.IsSigned);
            return contents;
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("Invalid signed-zone bundle structure.", exception);
        }
    }

    private static DnsRecord ReadRecord(ReadOnlySpan<byte> payload, ref int offset)
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
        Require(payload.Length - offset >= 8);
        var type = BinaryPrimitives.ReadUInt16BigEndian(payload[offset..]);
        var ttl = BinaryPrimitives.ReadUInt32BigEndian(payload[(offset + 2)..]);
        var lengthData = BinaryPrimitives.ReadUInt16BigEndian(payload[(offset + 6)..]);
        offset += 8;
        Require(lengthData <= payload.Length - offset);
        var record = new DnsRecord(name, type, ttl, payload.Slice(offset, lengthData));
        offset += lengthData;
        return record;
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Invalid versioned signed-zone bundle.");
    }
}
