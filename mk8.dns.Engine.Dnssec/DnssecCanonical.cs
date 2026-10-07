using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public static class DnssecCanonical
{
    public const int MaximumRrsetBytes = 1_048_576;

    public static byte[] GetRdata(DnsRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var data = record.GetData();
        var offset = 0;
        var names = 0;
        var tail = 0;
        switch (record.Type)
        {
            case 2 or 3 or 4 or 5 or 7 or 8 or 9 or 12 or 39:
                names = 1;
                break;
            case 6:
                names = 2;
                tail = 20;
                break;
            case 14 or 17:
                names = 2;
                break;
            case 15 or 18 or 21 or 36:
                offset = 2;
                names = 1;
                break;
            case 26:
                offset = 2;
                names = 2;
                break;
            case 33:
                offset = 6;
                names = 1;
                break;
            case 24 or 46:
                return LowerTrailingName(data, 18);
            case 30:
                return LowerTrailingName(data, 0);
            case 35:
                offset = NaptrReplacementOffset(data);
                names = 1;
                break;
            case 38:
                DnssecData.Require(data.Length >= 1 && data[0] <= 128);
                offset = 1 + (128 - data[0] + 7) / 8;
                names = data[0] == 0 ? 0 : 1;
                break;
            case 47:
                // RFC 6840: NSEC Next Domain Name is preserved, not downcased.
                _ = DnssecData.ReadName(data, ref offset);
                _ = NsecBitmap.Decode(data.AsSpan(offset));
                return data;
            default:
                // RFC 3597: newer/unknown RDATA, including SVCB/HTTPS, stays opaque.
                return data;
        }
        DnssecData.Require(offset <= data.Length);
        for (var index = 0; index < names; index++)
            DnssecData.LowerName(data, ref offset);
        DnssecData.Require(data.Length - offset == tail);
        return data;
    }

    private static byte[] LowerTrailingName(byte[] data, int offset)
    {
        DnssecData.LowerName(data, ref offset);
        DnssecData.Require(offset < data.Length);
        return data;
    }

    private static int NaptrReplacementOffset(ReadOnlySpan<byte> data)
    {
        var offset = 4;
        for (var field = 0; field < 3; field++)
        {
            DnssecData.Require(offset < data.Length);
            var length = data[offset++];
            DnssecData.Require(length <= data.Length - offset);
            offset += length;
        }
        return offset;
    }

    public static byte[] GetRrset(IReadOnlyList<DnsRecord> records, uint originalTtl, byte labels)
    {
        ArgumentNullException.ThrowIfNull(records);
        if (records.Count is 0 or > 10_000 || originalTtl > int.MaxValue)
            throw new ArgumentException("Invalid canonical RRset bounds.", nameof(records));
        var items = records.ToArray();
        if (items.Any(record => record is null))
            throw new ArgumentException("Null canonical records are not permitted.", nameof(records));
        var owner = items[0].Owner;
        var type = items[0].Type;
        if (items.Any(record => !record.Owner.Equals(owner) || record.Type != type))
            throw new ArgumentException("Canonicalization requires one owner and type.", nameof(records));
        var name = DnssecData.SignedOwner(owner, labels).ToWire();
        var values = new byte[items.Length][];
        long size = 0;
        for (var index = 0; index < items.Length; index++)
        {
            var value = GetRdata(items[index]);
            size += name.Length + 10L + value.Length;
            if (size > MaximumRrsetBytes)
                throw new ArgumentException("Canonical RRset exceeds its byte bound.", nameof(records));
            values[index] = value;
        }
        Array.Sort(values, ByteOrder.Instance);
        for (var index = 1; index < values.Length; index++)
            if (values[index].AsSpan().SequenceEqual(values[index - 1]))
                throw new FormatException("Duplicate canonical RRset data.");
        using var output = new MemoryStream((int)size);
        Span<byte> header = stackalloc byte[10];
        BinaryPrimitives.WriteUInt16BigEndian(header, type);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 1);
        BinaryPrimitives.WriteUInt32BigEndian(header[4..], originalTtl);
        foreach (var value in values)
        {
            output.Write(name);
            BinaryPrimitives.WriteUInt16BigEndian(header[8..], (ushort)value.Length);
            output.Write(header);
            output.Write(value);
        }
        return output.ToArray();
    }

    private sealed class ByteOrder : IComparer<byte[]>
    {
        internal static ByteOrder Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y);
    }
}
