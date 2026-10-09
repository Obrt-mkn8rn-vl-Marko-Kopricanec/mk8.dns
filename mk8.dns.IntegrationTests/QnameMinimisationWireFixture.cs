using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;

namespace Mk8.Dns.IntegrationTests;

internal sealed class QnameMinimisationWireFixture(bool corrupt, bool deep) : IDisposable
{
    private readonly Level root = new("example.");
    private readonly Level child = new("child.example.");
    internal DnsName Name { get; } = DnsName.Parse(deep ? "private.team.example." : "private.child.example.");
    internal DnssecTrustAnchor Anchor => new(root.Key);
    internal TimeProvider Clock { get; } = new FixedClock();
    internal static EcdsaP256DnssecVerifier Verifier { get; } = new();

    internal byte[] Reply(byte[] query, DnsServerEndpoint childServer, bool rootRole)
    {
        var question = DnsMessageCodec.DecodeQuery(query).Question!;
        var level = rootRole ? root : child;
        DnsRecord[] answers = []; DnsRecord[] authority = []; DnsRecord[] additional = []; var aa = true;
        if (question.Type == 48) answers = [level.Key, level.Sign([level.Key])];
        else if (rootRole && question.Type == 43)
        {
            var ds = DnssecKeys.CreateDs(child.Key, 300); answers = [ds, root.Sign([ds])];
        }
        else if (rootRole && question.Name.IsSubdomainOf(child.Origin))
        {
            aa = false; var ns = DnsName.Parse("ns.child.example.");
            authority = [new DnsRecord(child.Origin, 2, 300, ns.ToWire())];
            additional = [new DnsRecord(ns, childServer.GetAddress().Length == 4 ? (ushort)1 : (ushort)28, 300, childServer.GetAddress())];
        }
        else if (question.Type == 2)
        {
            var soa = new DnsRecord(level.Origin, 6, 300, [.. DnsName.Parse("ns.example.").ToWire(), .. DnsName.Parse("hostmaster.example.").ToWire(),
                0, 0, 0, 1, 0, 0, 1, 44, 0, 0, 1, 44, 0, 0, 1, 44, 0, 0, 0, 90]);
            var nsec = new DnsRecord(question.Name, 47, 300, [.. level.Origin.ToWire(), .. NsecBitmap.Encode([1, 46, 47])]);
            var signature = level.Sign([nsec]);
            if (corrupt) { var bytes = signature.GetData(); bytes[^1] ^= 1; signature = new DnsRecord(signature.Owner, 46, signature.Ttl, bytes); }
            authority = [soa, nsec, level.Sign([soa]), signature];
        }
        else
        {
            var address = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 43]); answers = [address, level.Sign([address])];
        }
        return Pack(query, question, answers, authority, additional, aa);
    }

    private static byte[] Pack(byte[] query, DnsQuestion question, DnsRecord[] answers, DnsRecord[] authority, DnsRecord[] additional, bool aa)
    {
        var rows = answers.Concat(authority).Concat(additional).Select(Encode).ToArray();
        var end = 12 + question.Name.ToWire().Length + 4; var result = new byte[end + rows.Sum(row => row.Length) + 11];
        query.AsSpan(0, end).CopyTo(result); DnssecUpstreamFixture.Write16(result, 2, (ushort)(aa ? 0x8430 : 0x8030));
        DnssecUpstreamFixture.Write16(result, 6, (ushort)answers.Length); DnssecUpstreamFixture.Write16(result, 8, (ushort)authority.Length);
        DnssecUpstreamFixture.Write16(result, 10, (ushort)(additional.Length + 1));
        foreach (var row in rows) { row.CopyTo(result, end); end += row.Length; }
        DnssecUpstreamFixture.Write16(result, end + 1, 41); DnssecUpstreamFixture.Write16(result, end + 3, 1232);
        DnssecUpstreamFixture.Write16(result, end + 7, 0x8000); return result;
    }

    private static byte[] Encode(DnsRecord record)
    {
        var name = record.GetOwnerWire(); var data = record.GetData(); var bytes = new byte[name.Length + 10 + data.Length];
        name.CopyTo(bytes, 0); DnssecUpstreamFixture.Write16(bytes, name.Length, record.Type); DnssecUpstreamFixture.Write16(bytes, name.Length + 2, 1);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(name.Length + 4), record.Ttl); DnssecUpstreamFixture.Write16(bytes, name.Length + 8, (ushort)data.Length);
        data.CopyTo(bytes, name.Length + 10); return bytes;
    }
    public void Dispose() { root.Dispose(); child.Dispose(); }
    private sealed class Level : IDisposable
    {
        private readonly EcdsaP256DnssecSigningKey key = EcdsaP256DnssecSigningKey.Create();
        internal Level(string origin) { Origin = DnsName.Parse(origin); Key = DnssecKeys.CreateDnskey(Origin, 300, key.GetPublicKey()); }
        internal DnsName Origin { get; }
        internal DnsRecord Key { get; }
        internal DnsRecord Sign(DnsRecord[] records) => DnssecRrsetSigner.Sign(records, Key, key, Verifier, new DnssecSignatureWindow(99, 10000));
        public void Dispose() => key.Dispose();
    }
    private sealed class FixedClock : TimeProvider
    {
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
