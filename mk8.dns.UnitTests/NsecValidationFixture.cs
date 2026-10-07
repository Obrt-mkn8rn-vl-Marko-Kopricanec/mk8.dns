using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

internal sealed class NsecValidationFixture : IDisposable
{
    private readonly DnssecChainFixture chain = new();
    internal NsecValidationFixture()
    {
        Keys = chain.Trust();
        var data = AuthorityFixture.Zone().Soa.GetData();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(data.Length - 4), 300);
        Soa = new DnsRecord(DnsName.Parse("example."), 6, 300, data);
    }
    internal DnssecChainValidator Validator => chain.Validator;
    internal AuthenticatedDnskeySet Keys { get; }
    internal DnsRecord Soa { get; }
    internal DnssecChainFixture.ClockProvider Clock => chain.Clock;
    internal DnsRecord Nsec(string owner, string next, params ushort[] types)
        => new(DnsName.Parse(owner), 47, Math.Min(Soa.Ttl, Soa.GetSoaMinimum()), [.. DnsName.Parse(next).ToWire(), .. NsecBitmap.Encode(types.Concat([(ushort)46, (ushort)47]))]);
    internal DnsRecord Sign(DnsRecord record, DnssecSignatureWindow? window = null)
        => DnssecChainFixture.Sign([record], chain.ParentZskRecord, chain.ParentZsk, window);
    internal DnsRecord[] SignAll(IEnumerable<DnsRecord> nsecs, bool soa = true)
        => (soa ? nsecs.Prepend(Soa) : nsecs).Select(record => Sign(record)).ToArray();
    internal static DnsQuestion Question(string name, ushort type = 1) => new(DnsName.Parse(name), type, 1);
    internal bool NameError(string name, DnsRecord[] nsecs, out uint ttl, DnsRecord[]? sigs = null)
        => Validator.TryAuthenticateNameError(Keys, Question(name), [Soa], nsecs, sigs ?? SignAll(nsecs), out ttl);
    internal bool NoData(string name, ushort type, DnsRecord[] nsecs, out uint ttl, DnsRecord[]? sigs = null)
        => Validator.TryAuthenticateNoData(Keys, Question(name, type), [Soa], nsecs, sigs ?? SignAll(nsecs), out ttl);
    internal DnsRecord[] Expanded(string source, string owner, ushort type = 1)
    {
        var original = type == 5 ? new DnsRecord(DnsName.Parse(source), 5, 300, DnsName.Parse("target.example.").ToWire()) : DnssecFixture.A(source);
        return [original.WithOwner(DnsName.Parse(owner)), Sign(original).WithOwner(DnsName.Parse(owner))];
    }
    internal bool Wildcard(string source, string owner, DnsRecord[] nsecs, out uint ttl, ushort type = 1)
    {
        var records = Expanded(source, owner, type);
        return Validator.TryAuthenticateWildcard(Keys, Question(owner, type), [records[0]], nsecs,
            [records[1], .. SignAll(nsecs, soa: false)], out ttl);
    }
    internal AuthenticatedDnskeySet Child => chain.AuthenticateChild();
    internal AuthenticatedDnskeySet TrustWith(DnssecChainValidator validator)
    {
        Assert.True(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(chain.ParentCskRecord), chain.ParentRecords, [chain.ParentSignature], out var keys));
        return keys;
    }
    public void Dispose() => chain.Dispose();
}
