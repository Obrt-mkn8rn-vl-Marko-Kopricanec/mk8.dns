using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;

namespace Mk8.Dns.IntegrationTests;

internal sealed class OnlineNsec3WireFixture : IDisposable
{
    private readonly EcdsaP256DnssecSigningKey rootKey = EcdsaP256DnssecSigningKey.Create();
    private readonly EcdsaP256DnssecSigningKey childKey = EcdsaP256DnssecSigningKey.Create();
    private readonly bool unsigned;
    private readonly bool optOut;
    internal OnlineNsec3WireFixture(bool unsigned = false, bool optOut = false)
    {
        this.unsigned = unsigned; this.optOut = optOut;
        RootKey = DnssecKeys.CreateDnskey(DnsName.Parse("example."), 300, rootKey.GetPublicKey());
        ChildKey = DnssecKeys.CreateDnskey(DnsName.Parse("child.example."), 300, childKey.GetPublicKey());
    }
    internal DnsRecord RootKey { get; }
    internal DnsRecord ChildKey { get; }
    internal DnssecTrustAnchor Anchor => new(RootKey);
    internal TimeProvider Clock { get; } = new FixedClock();
    internal static EcdsaP256DnssecVerifier Verifier { get; } = new();

    internal byte[] Reply(byte[] query, DnsServerEndpoint childServer, bool child, bool corrupt = false)
    {
        var question = DnsMessageCodec.DecodeQuery(query).Question!;
        var origin = child ? ChildKey.Owner : RootKey.Owner;
        DnsRecord[] answers = []; DnsRecord[] authority = []; DnsRecord[] additional = []; var aa = true; ushort code = 0;
        if (question.Type == 48) { var key = child ? ChildKey : RootKey; answers = [key, Sign(key, child)]; }
        else if (!child && question.Type == 43 && !unsigned)
        {
            var ds = DnssecKeys.CreateDs(ChildKey, 300); answers = [ds, Sign(ds, child: false)];
        }
        else if (!child && question.Name.IsSubdomainOf(ChildKey.Owner) && question.Type != 43)
        {
            aa = false; var ns = DnsName.Parse("ns.child.example."); var address = childServer.GetAddress();
            authority = [new DnsRecord(ChildKey.Owner, 2, 300, ns.ToWire())]; additional = [new DnsRecord(ns, address.Length == 4 ? (ushort)1 : (ushort)28, 300, address)];
        }
        else
        {
            var proofs = Proofs(question, origin, child);
            var wildcard = question.Name.ToString().StartsWith("new.", StringComparison.Ordinal) && question.Type == 1;
            if (wildcard)
            {
                var record = new DnsRecord(origin.PrependLabel("*"u8), 1, 300, [192, 0, 2, 43]);
                answers = [record.WithOwner(question.Name), Sign(record, child).WithOwner(question.Name)];
                authority = [.. proofs, .. proofs.Select(record => Sign(record, child))];
            }
            else
            {
                var soa = Soa(origin);
                authority = [soa, Sign(soa, child), .. proofs, .. proofs.Select(record => Sign(record, child))];
                code = question.Name.ToString().StartsWith("missing.", StringComparison.Ordinal) ? (ushort)3 : (ushort)0;
            }
        }
        if (corrupt) authority = authority.Select(record =>
        {
            if (record.Type != 46 || BinaryPrimitives.ReadUInt16BigEndian(record.GetData()) != 50) return record;
            var bytes = record.GetData(); bytes[^1] ^= 1; return new DnsRecord(record.Owner, 46, record.Ttl, bytes);
        }).ToArray();
        return EncodeReply(query, answers, authority, additional, aa, code);
    }

    private static byte[] EncodeReply(byte[] query, DnsRecord[] answers, DnsRecord[] authority, DnsRecord[] additional, bool aa, ushort code)
    {
        var end = 12 + DnsMessageCodec.DecodeQuery(query).Question!.Name.ToWire().Length + 4;
        var rows = answers.Concat(authority).Concat(additional).Select(Encode).ToArray();
        var result = new byte[end + rows.Sum(row => row.Length) + 11]; query.AsSpan(0, end).CopyTo(result);
        DnssecUpstreamFixture.Write16(result, 2, (ushort)((aa ? 0x8430 : 0x8030) | code));
        DnssecUpstreamFixture.Write16(result, 6, (ushort)answers.Length); DnssecUpstreamFixture.Write16(result, 8, (ushort)authority.Length);
        DnssecUpstreamFixture.Write16(result, 10, (ushort)(additional.Length + 1));
        foreach (var row in rows) { row.CopyTo(result, end); end += row.Length; }
        DnssecUpstreamFixture.Write16(result, end + 1, 41); DnssecUpstreamFixture.Write16(result, end + 3, 1232); DnssecUpstreamFixture.Write16(result, end + 7, 0x8000);
        if (result.Length > 1232) throw new InvalidOperationException("Fixture minimal proof exceeded its UDP advertisement.");
        return result;
    }

    private DnsRecord[] Proofs(DnsQuestion question, DnsName origin, bool child)
    {
        var entries = new Dictionary<DnsName, ushort[]>
        {
            [origin] = [2, 6, 46, 48],
            [origin.PrependLabel("www"u8)] = [1, 46],
            [origin.PrependLabel("empty"u8)] = [],
            [origin.PrependLabel("*"u8)] = [1, 46]
        };
        if (!child && !(unsigned && optOut)) entries[ChildKey.Owner] = unsigned ? [2] : [2, 43, 46];
        var sorted = entries.Select(item => (item.Key, Hash: Hash(item.Key), item.Value)).OrderBy(item => Convert.ToHexString(item.Hash), StringComparer.Ordinal).ToArray();
        var ring = sorted.Select((item, i) => new DnsRecord(origin.PrependLabel(Encoding.ASCII.GetBytes(Base32(item.Hash))), 50, 300,
            [1, optOut ? (byte)1 : (byte)0, 0, 0, 0, 20, .. sorted[(i + 1) % sorted.Length].Hash, .. item.Value.Length == 0 ? [] : NsecBitmap.Encode(item.Value)])).ToArray();
        DnsRecord? Match(DnsName name) => ring.SingleOrDefault(record => record.Owner.Equals(origin.PrependLabel(Encoding.ASCII.GetBytes(Base32(Hash(name))))));
        DnsRecord Cover(DnsName name)
        {
            var hash = Base32(Hash(name));
            return ring.Single(record =>
            {
                var owner = record.Owner.ToString().Split('.')[0]; var next = Base32(record.GetData().AsSpan(6, 20).ToArray());
                var low = string.CompareOrdinal(owner, hash); var high = string.CompareOrdinal(hash, next);
                return low != 0 && high != 0 && (string.CompareOrdinal(owner, next) < 0 ? low < 0 && high < 0 : low < 0 || high < 0);
            });
        }
        var exact = Match(question.Name); if (exact is not null) return [exact];
        var closest = question.Name.Parent; while (Match(closest) is null) closest = closest.Parent;
        var nextCloser = question.Name; while (!nextCloser.Parent.Equals(closest)) nextCloser = nextCloser.Parent;
        var wildcard = closest.PrependLabel("*"u8);
        return (question.Type == 43 ? new[] { Match(closest)!, Cover(nextCloser) }
            : question.Name.ToString().StartsWith("new.", StringComparison.Ordinal) && question.Type == 1 ? [Cover(nextCloser)]
            : new[] { Match(closest)!, Cover(nextCloser), Match(wildcard) ?? Cover(wildcard) }).Distinct().ToArray();
    }

    private DnsRecord Sign(DnsRecord record, bool child)
        => DnssecRrsetSigner.Sign([record], child ? ChildKey : RootKey, child ? childKey : rootKey, Verifier, new DnssecSignatureWindow(99, 10000));
    private static DnsRecord Soa(DnsName origin)
    {
        var bytes = new byte[20]; for (var i = 0; i < 20; i += 4) BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(i), i == 0 ? 1U : 60U);
        return new DnsRecord(origin, 6, 300, [.. origin.PrependLabel("ns"u8).ToWire(), .. origin.PrependLabel("hostmaster"u8).ToWire(), .. bytes]);
    }
    private static byte[] Hash(DnsName name) { using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1); hash.AppendData(name.ToWire()); return hash.GetHashAndReset(); }
    private static string Base32(byte[] bytes)
    {
        const string alphabet = "0123456789abcdefghijklmnopqrstuv"; var output = new StringBuilder(); var buffer = 0; var bits = 0;
        foreach (var value in bytes) { buffer = (buffer << 8) | value; bits += 8; while (bits >= 5) { bits -= 5; output.Append(alphabet[(buffer >> bits) & 31]); } }
        return output.ToString();
    }
    private static byte[] Encode(DnsRecord record)
    {
        var name = record.GetOwnerWire(); var data = record.GetData(); var bytes = new byte[name.Length + data.Length + 10]; name.CopyTo(bytes, 0);
        DnssecUpstreamFixture.Write16(bytes, name.Length, record.Type); DnssecUpstreamFixture.Write16(bytes, name.Length + 2, 1);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(name.Length + 4), record.Ttl); DnssecUpstreamFixture.Write16(bytes, name.Length + 8, (ushort)data.Length);
        data.CopyTo(bytes, name.Length + 10); return bytes;
    }
    public void Dispose() { rootKey.Dispose(); childKey.Dispose(); }
    private sealed class FixedClock : TimeProvider { public override long GetTimestamp() => 0; public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100); }
}
