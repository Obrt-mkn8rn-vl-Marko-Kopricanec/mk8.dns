using System.Buffers.Binary;
using System.Net;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.IntegrationTests;

internal sealed class RootPrimingWireFixture : IDisposable
{
    private readonly EcdsaP256DnssecSigningKey key = EcdsaP256DnssecSigningKey.Create();
    internal RootPrimingWireFixture(bool ipv6)
    {
        var root = DnsName.Parse(".");
        var records = new List<DnsRecord> { Soa(root), new(DnsName.Parse("www.fixture."), 1, 300, [192, 0, 2, 43]) };
        var address = ipv6 ? IPAddress.IPv6Loopback.GetAddressBytes() : IPAddress.Loopback.GetAddressBytes();
        foreach (var name in new[] { "ns0.fixture.", "ns1.fixture." })
        {
            records.Add(new DnsRecord(root, 2, 300, DnsName.Parse(name).ToWire()));
            records.Add(new DnsRecord(DnsName.Parse(name), ipv6 ? (ushort)28 : (ushort)1, 300, address));
        }
        var zone = new AuthoritativeZone(root, records);
        var signed = NsecZoneSigner.Sign(zone, key, OnlineDnssecWireFixture.Verifier, new DnssecSignatureWindow(99, 10000));
        Anchor = new DnssecTrustAnchor(signed.Dnskey);
        Catalog = new AuthoritativeCatalog([new ZoneContents(zone, signed.GetAllRecords().Where(record => record.Type is 46 or 47 or 48))],
            OnlineDnssecWireFixture.Verifier, Clock);
    }
    internal DnssecTrustAnchor Anchor { get; }
    internal AuthoritativeCatalog Catalog { get; }
    internal TimeProvider Clock { get; } = new FixedClock();

    private static DnsRecord Soa(DnsName owner)
    {
        var numbers = new byte[20];
        foreach (var (offset, value) in new (int, uint)[] { (0, 1), (4, 3600), (8, 600), (12, 86400), (16, 60) })
            BinaryPrimitives.WriteUInt32BigEndian(numbers.AsSpan(offset), value);
        return new DnsRecord(owner, 6, 300, [.. DnsName.Parse("ns0.fixture.").ToWire(), .. DnsName.Parse("hostmaster.fixture.").ToWire(), .. numbers]);
    }
    public void Dispose() => key.Dispose();
    private sealed class FixedClock : TimeProvider
    {
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
