using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

internal sealed partial class DnssecResolutionProof
{
    internal DnsRecord[] ClientAnswerSignatures(DnssecResolutionClock clock, long now, uint lifetime)
        => ClientSignatures(records, clock, now, lifetime);

    internal DnsRecord[] ClientAuthority(DnssecResolutionClock clock, long now, uint lifetime)
        => [.. Age(nsecs, clock, now).Select(record => record.WithTtl(Math.Min(record.Ttl, lifetime))),
            .. ClientSignatures(soa.Concat(nsecs), clock, now, lifetime)];

    private DnsRecord[] ClientSignatures(IEnumerable<DnsRecord> covered, DnssecResolutionClock clock, long now, uint lifetime)
    {
        var sets = covered.Select(record => (record.Owner, record.Type)).ToHashSet();
        return [.. Age(signatures, clock, now).Where(record =>
                sets.Contains((record.Owner, BinaryPrimitives.ReadUInt16BigEndian(record.GetData()))))
            .Select(record => record.WithTtl(Math.Min(record.Ttl, lifetime)))];
    }
}
