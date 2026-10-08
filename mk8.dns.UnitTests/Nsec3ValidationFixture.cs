using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.UnitTests;

internal sealed class Nsec3ValidationFixture : IDisposable
{
    private readonly DnssecChainFixture chain = new();
    internal Nsec3ValidationFixture() => Keys = chain.Trust();
    internal DnssecChainValidator Validator => chain.Validator;
    internal AuthenticatedDnskeySet Keys { get; }
    internal DnssecChainFixture.ClockProvider Clock => chain.Clock;
    internal DnsRecord Soa { get; } = AuthorityFixture.Zone().Soa;
    internal DnsRecord Sign(DnsRecord record, DnssecSignatureWindow? window = null)
        => DnssecChainFixture.Sign([record], chain.ParentZskRecord, chain.ParentZsk, window);
    internal DnsRecord[] SignAll(DnsRecord[] records, bool soa = true)
        => (soa ? records.Prepend(Soa) : records).Select(record => Sign(record)).ToArray();
    internal static DnsRecord[] Ring(bool wildcard = false, bool optOut = false, byte[]? salt = null)
    {
        (string Name, ushort[] Types)[] entries = [
            ("example.", [2, 6, 46, 48]), ("www.example.", [1, 46]), ("empty.example.", []),
            ("leaf.empty.example.", [1, 46]), ("child.example.", [2]), ("alias.example.", [39, 46]),
        ];
        if (wildcard) entries = [.. entries, ("*.example.", [1, 46])];
        var sorted = entries.Select(item => (Hash: Hash(item.Name, salt), item.Types)).OrderBy(item => Convert.ToHexString(item.Hash), StringComparer.Ordinal).ToArray();
        return sorted.Select((item, index) => Record(item.Hash, sorted[(index + 1) % sorted.Length].Hash, item.Types, optOut, salt)).ToArray();
    }
    internal static byte[] Hash(string name, byte[]? salt = null)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        hash.AppendData(DnsName.Parse(name).ToWire());
        hash.AppendData(salt ?? []);
        return hash.GetHashAndReset();
    }
    internal static DnsRecord Record(byte[] owner, byte[] next, ushort[] types, bool optOut = false, byte[]? salt = null)
    {
        salt ??= [];
        return new DnsRecord(DnsName.Parse(Base32(owner) + ".example."), 50, 300,
            [1, optOut ? (byte)1 : (byte)0, 0, 0, (byte)salt.Length, .. salt, 20, .. next, .. types.Length == 0 ? [] : NsecBitmap.Encode(types)]);
    }
    internal static string Base32(byte[] data)
    {
        const string alphabet = "0123456789abcdefghijklmnopqrstuv";
        var buffer = 0;
        var bits = 0;
        var result = new System.Text.StringBuilder();
        foreach (var octet in data)
        {
            buffer = (buffer << 8) | octet;
            bits += 8;
            while (bits >= 5) { bits -= 5; result.Append(alphabet[(buffer >> bits) & 31]); }
        }
        return result.ToString();
    }
    internal bool NameError(string name, DnsRecord[] proofs, out uint ttl, DnsRecord[]? signatures = null)
        => Validator.TryAuthenticateNsec3NameError(Keys, NsecValidationFixture.Question(name), [Soa], proofs, signatures ?? SignAll(proofs), out ttl);
    internal bool NoData(string name, ushort type, DnsRecord[] proofs, out uint ttl, DnsRecord[]? signatures = null)
        => Validator.TryAuthenticateNsec3NoData(Keys, NsecValidationFixture.Question(name, type), [Soa], proofs, signatures ?? SignAll(proofs), out ttl);
    internal bool Ds(string name, DnsRecord[] proofs, out uint ttl, out bool optOut)
        => Validator.TryAuthenticateNsec3DsAbsence(Keys, DnsName.Parse(name), proofs, SignAll(proofs, soa: false), out ttl, out optOut);
    internal DnsRecord[] Expanded(string source, string target)
    {
        var data = DnssecFixture.A(source);
        return [data.WithOwner(DnsName.Parse(target)), Sign(data).WithOwner(DnsName.Parse(target))];
    }
    internal bool Wildcard(string source, string target, DnsRecord[] proofs, out uint ttl)
    {
        var data = Expanded(source, target);
        return Validator.TryAuthenticateNsec3Wildcard(Keys, NsecValidationFixture.Question(target), [data[0]], proofs,
            [data[1], .. SignAll(proofs, soa: false)], out ttl);
    }
    internal AuthenticatedDnskeySet TrustWith(DnssecChainValidator validator)
    {
        Xunit.Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(chain.ParentCskRecord), chain.ParentRecords, [chain.ParentSignature], out var keys));
        return keys;
    }
    public void Dispose() => chain.Dispose();
}
