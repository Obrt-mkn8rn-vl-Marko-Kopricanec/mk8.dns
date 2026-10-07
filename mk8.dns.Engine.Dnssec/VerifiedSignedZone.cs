using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed class VerifiedSignedZone
{
    private readonly Dictionary<DnsName, DnsRecord[]> records;
    private readonly Dictionary<(DnsName Owner, ushort Type), DnsRecord> signatures;
    private readonly DnsRecord[] denial;

    internal VerifiedSignedZone(ZoneContents contents, DnsRecord dnskey, DnssecSignatureWindow window, Dictionary<(DnsName Owner, ushort Type), DnsRecord> signatures)
    {
        Contents = contents;
        Dnskey = dnskey;
        Window = window;
        this.signatures = signatures;
        records = contents.GetAllRecords().GroupBy(record => record.Owner).ToDictionary(group => group.Key, group => group.ToArray());
        denial = contents.GetSecurityRecords().Where(record => record.Type == 47).OrderBy(record => record.Owner, DnssecNameOrder.Instance).ToArray();
    }

    public ZoneContents Contents { get; }
    public DnsRecord Dnskey { get; }
    public DnssecSignatureWindow Window { get; }
    public bool IsAvailable(uint now) => Window.Contains(now);
    public uint BoundTtl(uint ttl, uint now) => Window.Contains(now) ? Math.Min(ttl, unchecked(Window.Expiration - now)) : 0;
    public IReadOnlyList<DnsRecord> GetRecords(DnsName name) => records.TryGetValue(name, out var value) ? Array.AsReadOnly(value) : Array.Empty<DnsRecord>();
    public DnsRecord? GetSignature(DnsName owner, ushort type) => signatures.GetValueOrDefault((owner, type));

    public DnsRecord GetCover(DnsName name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!name.IsSubdomainOf(Contents.Source.Origin))
            throw new ArgumentException("Denial lookup is outside the verified zone.", nameof(name));
        var low = 0;
        var high = denial.Length - 1;
        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            var comparison = DnssecNameOrder.Instance.Compare(denial[middle].Owner, name);
            if (comparison == 0)
                return denial[middle];
            if (comparison < 0)
                low = middle + 1;
            else
                high = middle - 1;
        }
        return denial[high < 0 ? denial.Length - 1 : high];
    }
}
