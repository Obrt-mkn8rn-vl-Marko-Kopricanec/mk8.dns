using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed class AuthenticatedDnskeySet
{
    internal AuthenticatedDnskeySet(DnssecChainValidator creator, DnsName origin, DnsRecord[] records,
        long received, uint ttl, DnssecSignatureWindow[] windows, int depth)
    {
        Creator = creator;
        Origin = origin;
        Records = Array.AsReadOnly((DnsRecord[])records.Clone());
        UsableKeys = records.Where(DnssecValidationInput.IsUsableKey).ToArray();
        Received = received;
        Ttl = ttl;
        Windows = Array.AsReadOnly((DnssecSignatureWindow[])windows.Clone());
        Depth = depth;
    }

    public DnsName Origin { get; }
    public IReadOnlyList<DnsRecord> Records { get; }
    public int Depth { get; }
    internal DnssecChainValidator Creator { get; }
    internal DnsRecord[] UsableKeys { get; }
    internal long Received { get; }
    internal uint Ttl { get; }
    internal IReadOnlyList<DnssecSignatureWindow> Windows { get; }
}
