using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure;

namespace Mk8.Dns.UnitTests;

internal static class SignedAuthorityFixture
{
    internal static ZoneContents Contents(AuthoritativeZone source, DnssecSignatureWindow? window = null)
    {
        using var key = DnssecFixture.Key();
        var signed = NsecZoneSigner.Sign(source, key, DnssecFixture.Verifier, window ?? DnssecFixture.Window);
        return new ZoneContents(source, signed.GetAllRecords().Where(record => record.Type is 46 or 47 or 48));
    }

    internal static AuthoritativeCatalog Catalog(params AuthoritativeZone[] zones) => new(zones.Select(zone => Contents(zone)), DnssecFixture.Verifier, new Clock());
    internal static DnsQuestion Question(string name, ushort type = 1) => new(DnsName.Parse(name), type, 1);
    internal static ZoneContents Replace(ZoneContents contents, DnsRecord original, DnsRecord replacement)
        => new(contents.Source, contents.GetSecurityRecords().Select(record => ReferenceEquals(record, original) ? replacement : record));

    internal static ZoneBundleAdapter Codec(IDnssecSigningKey key, Clock time, uint lifetime = 3600)
        => new(new DnssecZoneSigningService(new Dictionary<DnsName, DnssecSigningPolicy> { [DnssecFixture.Origin] = new(key, lifetime) }, DnssecFixture.Verifier, time));

    internal sealed class Clock : TimeProvider
    {
        internal uint Seconds { get; set; } = 1000;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Seconds);
    }
}
