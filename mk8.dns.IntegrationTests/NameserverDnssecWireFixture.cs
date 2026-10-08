using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;

namespace Mk8.Dns.IntegrationTests;

internal sealed class NameserverDnssecWireFixture : IDisposable
{
    private readonly Level root = new("example.");
    private readonly Level provider = new("provider.example.");
    private readonly Level child = new("child.example.");
    internal DnssecTrustAnchor Anchor => new(root.Key);
    internal static EcdsaP256DnssecVerifier Verifier { get; } = new();
    internal TimeProvider Clock { get; } = new FixedClock();

    internal byte[] Reply(byte[] query, DnsServerEndpoint authorityServer, bool rootRole, int defect)
    {
        var question = DnsMessageCodec.DecodeQuery(query).Question!;
        var level = rootRole ? root : question.Name.IsSubdomainOf(provider.Origin) ? provider : child;
        DnsRecord[] answers = []; DnsRecord[] authority = []; DnsRecord[] additional = []; var aa = true;
        if (question.Type == 48) answers = [level.Key, level.Sign(level.Key)];
        else if (rootRole && question.Type == 43)
        {
            var selected = question.Name.Equals(provider.Origin) ? provider : child;
            var ds = DnssecKeys.CreateDs(selected.Key, 300, 4); answers = [ds, root.Sign(ds)];
        }
        else if (rootRole)
        {
            aa = false; var selected = question.Name.IsSubdomainOf(provider.Origin) ? provider : child;
            var target = DnsName.Parse(selected == provider ? "auth.provider.example." : "ns.provider.example.");
            authority = [new DnsRecord(selected.Origin, 2, 300, target.ToWire())];
            if (selected == provider)
            {
                var address = authorityServer.GetAddress(); additional = [new DnsRecord(target, address.Length == 4 ? (ushort)1 : (ushort)28, 300, address)];
            }
            else additional = [new DnsRecord(target, 1, 300, [192, 0, 2, 99])];
        }
        else if (level == provider)
        {
            var address = authorityServer.GetAddress(); var type = address.Length == 4 ? (ushort)1 : (ushort)28;
            if (question.Type == type)
            {
                var record = new DnsRecord(question.Name, type, 7, address); answers = [record, level.Sign(record)];
            }
            else
            {
                var soa = Soa(provider.Origin); var nsec = new DnsRecord(question.Name, 47, 300,
                    [.. provider.Origin.ToWire(), .. NsecBitmap.Encode([type, 46, 47])]);
                authority = [soa, nsec, level.Sign(soa), level.Sign(nsec)];
            }
        }
        else
        {
            var record = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 43]); answers = [record, level.Sign(record)];
        }
        var corrupt = defect == 1 && rootRole && question.Type == 43 && question.Name.Equals(child.Origin)
            || defect == 2 && level == provider && question.Type is 1 or 28;
        return EncodeReply(query, question, answers, authority, additional, aa, corrupt);
    }

    private static byte[] EncodeReply(byte[] query, DnsQuestion question, DnsRecord[] answers, DnsRecord[] authority,
        DnsRecord[] additional, bool aa, bool corrupt)
    {
        var rows = answers.Concat(authority).Concat(additional).Select(record => Encode(record, corrupt)).ToArray();
        var end = 12 + question.Name.ToWire().Length + 4; var result = new byte[end + rows.Sum(row => row.Length) + 11];
        query.AsSpan(0, end).CopyTo(result); DnssecUpstreamFixture.Write16(result, 2, (ushort)(aa ? 0x8430 : 0x8030));
        DnssecUpstreamFixture.Write16(result, 6, (ushort)answers.Length); DnssecUpstreamFixture.Write16(result, 8, (ushort)authority.Length);
        DnssecUpstreamFixture.Write16(result, 10, (ushort)(additional.Length + 1));
        foreach (var row in rows) { row.CopyTo(result, end); end += row.Length; }
        DnssecUpstreamFixture.Write16(result, end + 1, 41); DnssecUpstreamFixture.Write16(result, end + 3, 1232);
        DnssecUpstreamFixture.Write16(result, end + 7, 0x8000); return result;
    }

    private static DnsRecord Soa(DnsName origin)
    {
        var bytes = new byte[20]; for (var index = 0; index < 20; index += 4) BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(index), 60);
        return new DnsRecord(origin, 6, 300, [.. origin.PrependLabel("ns"u8).ToWire(), .. origin.PrependLabel("hostmaster"u8).ToWire(), .. bytes]);
    }
    private static byte[] Encode(DnsRecord record, bool corrupt)
    {
        var data = record.GetData(); if (corrupt && record.Type == 46) data[^1] ^= 1;
        var name = record.GetOwnerWire(); var result = new byte[name.Length + 10 + data.Length]; name.CopyTo(result, 0);
        DnssecUpstreamFixture.Write16(result, name.Length, record.Type); DnssecUpstreamFixture.Write16(result, name.Length + 2, 1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(name.Length + 4), record.Ttl);
        DnssecUpstreamFixture.Write16(result, name.Length + 8, (ushort)data.Length); data.CopyTo(result, name.Length + 10); return result;
    }
    public void Dispose() { root.Dispose(); provider.Dispose(); child.Dispose(); }
    private sealed class Level : IDisposable
    {
        private readonly EcdsaP256DnssecSigningKey key = EcdsaP256DnssecSigningKey.Create();
        internal Level(string origin) { Origin = DnsName.Parse(origin); Key = DnssecKeys.CreateDnskey(Origin, 300, key.GetPublicKey()); }
        internal DnsName Origin { get; }
        internal DnsRecord Key { get; }
        internal DnsRecord Sign(DnsRecord record) => DnssecRrsetSigner.Sign([record], Key, key, Verifier, new DnssecSignatureWindow(99, 10000));
        public void Dispose() => key.Dispose();
    }
    private sealed class FixedClock : TimeProvider { public override long GetTimestamp() => 0; public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100); }
}
