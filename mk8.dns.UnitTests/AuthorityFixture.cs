using System.Buffers.Binary;
using System.Text;
using Mk8.Dns.Domain;

namespace Mk8.Dns.UnitTests;

internal static class AuthorityFixture
{
    internal static DnsRecord Record(string owner, ushort type, byte[] data, uint ttl = 300) => new(DnsName.Parse(owner), type, ttl, data);

    internal static AuthoritativeZone Zone(params DnsRecord[] records) => ZoneAt("example.", records);

    internal static AuthoritativeZone ZoneAt(string origin, params DnsRecord[] records)
    {
        var soa = DnsName.Parse("ns." + origin).ToWire().Concat(DnsName.Parse("hostmaster." + origin).ToWire()).Concat(new byte[20]).ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(soa.Length - 20), 10);
        BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(soa.Length - 4), 60);
        return new AuthoritativeZone(DnsName.Parse(origin), new[]
        {
            Record(origin, 6, soa, 3600),
            Record(origin, 2, DnsName.Parse("ns." + origin).ToWire()),
        }.Concat(records));
    }

    internal static byte[] DsData(byte tag) => new byte[] { 0, tag, 8, 2 }.Concat(Enumerable.Repeat((byte)3, 32)).ToArray();

    internal static byte[] Query(string name = "www.example.", ushort type = 1, ushort? edns = null, byte version = 0, ushort flags = 0x0100, ushort queryClass = 1)
    {
        var wire = string.Equals(name, ".", StringComparison.Ordinal) ? new byte[] { 0 } : name.TrimEnd('.').Split('.').SelectMany(label => new[] { (byte)label.Length }.Concat(Encoding.ASCII.GetBytes(label))).Append((byte)0).ToArray();
        var result = new byte[12 + wire.Length + 4 + (edns.HasValue ? 11 : 0)];
        BinaryPrimitives.WriteUInt16BigEndian(result, 0xabcd);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        wire.CopyTo(result, 12);
        var offset = 12 + wire.Length;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), type);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 2), queryClass);
        if (edns.HasValue)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), 1);
            offset += 4;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 1), 41);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 3), edns.Value);
            result[offset + 6] = version;
        }
        return result;
    }
}
