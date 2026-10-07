using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

internal sealed record DnssecReceivedEvidence(DnsUpstreamEvidence Evidence, long Received)
{
    internal DnsRecord[] Age(IEnumerable<DnsRecord> records, DnssecResolutionClock clock)
    {
        var now = clock.GetTimestamp();
        return records.Select(record => record.WithTtl(clock.Age(record.Ttl, Received, now))).ToArray();
    }
}
