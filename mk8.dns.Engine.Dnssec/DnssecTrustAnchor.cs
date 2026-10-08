using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed class DnssecTrustAnchor
{
    public DnssecTrustAnchor(DnsRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (DnssecData.IsWildcard(record.Owner))
            throw new ArgumentException("This anchor profile excludes leading-wildcard origins.", nameof(record));
        var data = record.GetData();
        if (record.Type == 48)
        {
            if (!DnssecValidationInput.IsUsableKey(record))
                throw new ArgumentException("Supply a usable algorithm-8, algorithm-13 or algorithm-14 zone DNSKEY anchor.", nameof(record));
        }
        else if (record.Type != 43 || data.Length < 4 || data[2] is not (8 or 13 or 14)
            || !(data[3] == 2 && data.Length == 36 || data[3] == 4 && data.Length == 52))
            throw new ArgumentException("Supply an algorithm-8/13/14 DNSKEY or SHA-256/SHA-384 DS anchor.", nameof(record));
        Record = record;
    }

    // Operator pins have no DNS TTL lease; obtained DNSKEY RRsets still do.
    public DnsRecord Record { get; }
    public DnsName Origin => Record.Owner;

    internal bool Matches(DnsRecord key) => Record.Type == 48
        ? key.Owner.Equals(Origin) && CryptographicOperations.FixedTimeEquals(key.GetData(), Record.GetData())
        : DnssecValidationInput.MatchesDs(Record, key);
}
