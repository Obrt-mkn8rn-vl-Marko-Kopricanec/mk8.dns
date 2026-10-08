using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;

namespace Mk8.Dns.IntegrationTests;

internal sealed class P384DnssecWireFixture : IDisposable
{
    private readonly ECDsa parentKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    private readonly ECDsa childKey;
    private readonly byte childAlgorithm;
    internal P384DnssecWireFixture(bool p256Child)
    {
        childAlgorithm = p256Child ? (byte)13 : (byte)14;
        childKey = ECDsa.Create(p256Child ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        Key = PublicRecord(DnsName.Parse("example."), parentKey, 14);
        ChildKey = PublicRecord(DnsName.Parse("child.example."), childKey, childAlgorithm);
    }

    private static DnsRecord PublicRecord(DnsName origin, ECDsa key, byte algorithm)
    {
        var material = key.ExportParameters(false);
        return new DnsRecord(origin, 48, 300, [1, 1, 3, algorithm, .. material.Q.X!, .. material.Q.Y!]);
    }

    internal DnsRecord Key { get; }
    internal DnsRecord ChildKey { get; }
    internal static DnssecSignatureVerifier Verifier { get; } = new();
    internal TimeProvider Clock { get; } = new FixedClock();
    private static DnssecSignatureWindow Window { get; } = new(99, 1000);

    internal byte[] Reply(byte[] query, DnsServerEndpoint child, bool childRole, bool corrupt)
    {
        var question = DnsMessageCodec.DecodeQuery(query).Question ?? throw new FormatException("Fixture requires one ordinary question.");
        var end = 12 + question.Name.ToWire().Length + 4;
        DnsRecord[] answers; DnsRecord[] authority = []; DnsRecord[] additional = []; var aa = true;
        var key = childRole ? ChildKey : Key;
        if (question.Type == 48)
            answers = [key, Sign([key], childRole)];
        else if (question.Type == 43)
        {
            var ds = DnssecKeys.CreateDs(ChildKey, 300, 4); answers = [ds, Sign([ds])];
        }
        else if (!childRole)
        {
            answers = []; aa = false;
            var ns = DnsName.Parse("ns.child.example."); authority = [new DnsRecord(ChildKey.Owner, 2, 300, ns.ToWire())];
            var address = child.GetAddress(); additional = [new DnsRecord(ns, address.Length == 4 ? (ushort)1 : (ushort)28, 300, address)];
        }
        else
        {
            var record = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 43]);
            answers = [record, Sign([record], childRole: true)];
        }
        var packets = answers.Concat(authority).Concat(additional).Select(record => Encode(record, corrupt && (childRole || question.Type == 43))).ToArray();
        var result = new byte[end + packets.Sum(row => row.Length) + 11]; query.AsSpan(0, end).CopyTo(result);
        DnssecUpstreamFixture.Write16(result, 2, (ushort)(aa ? 0x8430 : 0x8030));
        DnssecUpstreamFixture.Write16(result, 6, (ushort)answers.Length); DnssecUpstreamFixture.Write16(result, 8, (ushort)authority.Length);
        DnssecUpstreamFixture.Write16(result, 10, (ushort)(additional.Length + 1));
        foreach (var row in packets) { row.CopyTo(result, end); end += row.Length; }
        DnssecUpstreamFixture.Write16(result, end + 1, 41); DnssecUpstreamFixture.Write16(result, end + 3, 1232);
        DnssecUpstreamFixture.Write16(result, end + 7, 0x8000); return result;
    }

    private DnsRecord Sign(DnsRecord[] records, bool childRole = false)
    {
        var first = records[0]; var header = new byte[18]; BinaryPrimitives.WriteUInt16BigEndian(header, first.Type);
        header[2] = childRole ? childAlgorithm : (byte)14; header[3] = (byte)first.Owner.LabelCount;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), 300); BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), Window.Expiration);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), Window.Inception); BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(16), DnssecKeys.KeyTag(childRole ? ChildKey : Key));
        byte[] prefix = [.. header, .. (childRole ? ChildKey : Key).GetOwnerWire()]; byte[] data = [.. prefix, .. DnssecCanonical.GetRrset(records, 300, header[3])];
        var digest = header[2] == 14 ? SHA384.HashData(data) : SHA256.HashData(data);
        return new DnsRecord(first.Owner, 46, 300, [.. prefix, .. (childRole ? childKey : parentKey).SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)]);
    }
    private static byte[] Encode(DnsRecord record, bool corrupt)
    {
        var name = record.GetOwnerWire(); var data = record.GetData(); if (corrupt && record.Type == 46) data[^1] ^= 1;
        var result = new byte[name.Length + 10 + data.Length]; name.CopyTo(result, 0);
        DnssecUpstreamFixture.Write16(result, name.Length, record.Type); DnssecUpstreamFixture.Write16(result, name.Length + 2, 1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(name.Length + 4), record.Ttl);
        DnssecUpstreamFixture.Write16(result, name.Length + 8, (ushort)data.Length); data.CopyTo(result, name.Length + 10); return result;
    }
    public void Dispose() { parentKey.Dispose(); childKey.Dispose(); }

    private sealed class FixedClock : TimeProvider
    {
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
