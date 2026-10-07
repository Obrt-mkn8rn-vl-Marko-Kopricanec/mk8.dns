using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.UnitTests;

internal static class DnssecUpstreamFixture
{
    internal static DnsQuestion Question { get; } = new(DnsName.Parse("www.example."), 1, 1);
    internal static DnsServerEndpoint Server { get; } = new([127, 0, 0, 1], 5300);
    internal static byte[] Query()
    {
        var name = Question.Name.ToWire();
        var result = new byte[name.Length + 16];
        Write16(result, 0, 42); Write16(result, 2, 0x0010); Write16(result, 4, 1);
        name.CopyTo(result, 12); Write16(result, name.Length + 12, 1); Write16(result, name.Length + 14, 1);
        return result;
    }
    internal static byte[] Record(DnsRecord record)
    {
        var owner = record.GetOwnerWire(); var data = record.GetData();
        var wire = new byte[owner.Length + data.Length + 10];
        owner.CopyTo(wire, 0); Write16(wire, owner.Length, record.Type); Write16(wire, owner.Length + 2, 1);
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(owner.Length + 4), record.Ttl);
        Write16(wire, owner.Length + 8, (ushort)data.Length); data.CopyTo(wire, owner.Length + 10);
        return wire;
    }
    internal static byte[] RawRecord(byte[] owner, ushort type, byte[] data, ushort recordClass = 1)
    {
        var wire = new byte[owner.Length + data.Length + 10]; owner.CopyTo(wire, 0);
        Write16(wire, owner.Length, type); Write16(wire, owner.Length + 2, recordClass);
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(owner.Length + 4), 300);
        Write16(wire, owner.Length + 8, (ushort)data.Length); data.CopyTo(wire, owner.Length + 10); return wire;
    }
    internal static byte[] Opt(byte extendedCode = 0, byte version = 0, ushort flags = 0x8000, byte[]? options = null, ushort payload = 4096)
    {
        options ??= [];
        var result = new byte[11 + options.Length]; Write16(result, 1, 41); Write16(result, 3, payload);
        result[5] = extendedCode; result[6] = version; Write16(result, 7, flags); Write16(result, 9, (ushort)options.Length); options.CopyTo(result, 11); return result;
    }
    internal static byte[] Packet(ushort flags = 0x8430, byte[][]? answers = null, byte[][]? authority = null, byte[][]? additional = null)
    {
        answers ??= []; authority ??= []; additional ??= [];
        var query = Query(); var result = new byte[query.Length + answers.Concat(authority).Concat(additional).Sum(row => row.Length)]; query.CopyTo(result, 0);
        Write16(result, 2, flags); Write16(result, 6, (ushort)answers.Length); Write16(result, 8, (ushort)authority.Length); Write16(result, 10, (ushort)additional.Length);
        var offset = query.Length;
        foreach (var row in answers.Concat(authority).Concat(additional)) { row.CopyTo(result, offset); offset += row.Length; }
        return result;
    }
    internal static void Write16(byte[] wire, int offset, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(offset), value);
}
