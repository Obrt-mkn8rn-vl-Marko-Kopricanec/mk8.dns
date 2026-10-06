using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;

namespace Mk8.Dns.IntegrationTests;

internal sealed class ControlFixture
{
    internal Guid Epoch { get; } = Guid.NewGuid();
    internal Guid Tenant { get; } = Guid.NewGuid();
    internal Guid Zone { get; } = Guid.NewGuid();
    internal byte[] Credential { get; } = RandomNumberGenerator.GetBytes(32);
    internal const string Node = "controlled-replica";

    internal ManagementGrant Grant(string origin = "example.") => new(Tenant, Zone, DnsName.Parse(origin), "operator-test", DateTimeOffset.UtcNow.AddHours(1), SHA256.HashData(Credential));

    internal ScopedManagementAuthorizer Authorizer() => new([Grant()], TimeProvider.System);

    internal ManagementRequest Edit(long expected = 0, byte address = 42, Guid? operation = null, string originText = "example.")
    {
        var origin = DnsName.Parse(originText).ToWire();
        var soa = DnsName.Parse("ns." + originText).ToWire().Concat(DnsName.Parse("hostmaster." + originText).ToWire()).Concat(new byte[20]).ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(soa.Length - 20), 55555);
        BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(soa.Length - 4), 30);
        return new ManagementRequest("edit", Tenant, Zone, operation ?? Guid.NewGuid(), expected, origin,
        [new ZoneRecordData(origin, 6, 300, soa), new ZoneRecordData(origin, 2, 300, DnsName.Parse("ns." + originText).ToWire()), new ZoneRecordData(DnsName.Parse("www." + originText).ToWire(), 1, 300, new byte[] { 192, 0, 2, address })], Credential);
    }
}
