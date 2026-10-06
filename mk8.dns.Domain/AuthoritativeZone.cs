namespace Mk8.Dns.Domain;

public sealed class AuthoritativeZone
{
    private readonly Dictionary<DnsName, DnsRecord[]> records = [];
    private readonly HashSet<DnsName> names = [];

    public AuthoritativeZone(DnsName origin, IEnumerable<DnsRecord> records)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(records);
        Origin = origin;
        var all = records.Take(10_001).ToArray();
        if (all.Length is 0 or > 10_000)
            throw new ArgumentException("Zone record count exceeds its bounds.", nameof(records));
        if (all.Sum(record => record.Owner.ToWire().Length + record.GetData().Length + 10) > ZoneSnapshot.MaximumPayloadBytes - 6)
            throw new ArgumentException("Zone data exceeds the bundle size bound.", nameof(records));
        foreach (var group in all.GroupBy(record => record.Owner))
        {
            if (!group.Key.IsSubdomainOf(origin))
                throw new ArgumentException("Record owner is outside the zone.", nameof(records));
            var items = group.ToArray();
            foreach (var rrset in items.GroupBy(record => record.Type))
            {
                if (rrset.Any(record => record.Ttl != rrset.First().Ttl)
                    || rrset.Select(record => Convert.ToHexString(record.GetCanonicalData())).Distinct(StringComparer.Ordinal).Count() != rrset.Count())
                    throw new ArgumentException("An RRset must have one TTL and distinct RDATA.", nameof(records));
            }
            if (items.Any(record => record.Type == 5) && (items.Length != 1 || group.Key.Equals(origin))
                || items.Count(record => record.Type == 39) > 1
                || items.Any(record => record.Type == 39) && items.Any(record => record.Type == 2) && !group.Key.Equals(origin)
                || items.Any(record => record.Type == 6) && !group.Key.Equals(origin))
                throw new ArgumentException("Invalid alias or SOA placement.", nameof(records));
            this.records.Add(group.Key, items);
            var ancestor = group.Key;
            while (true)
            {
                names.Add(ancestor);
                if (ancestor.Equals(origin))
                    break;
                ancestor = ancestor.Parent;
            }
        }
        var apex = GetRecords(origin);
        if (apex.Count(record => record.Type == 6) != 1 || !apex.Any(record => record.Type == 2))
            throw new ArgumentException("A zone requires exactly one apex SOA and apex NS data.", nameof(records));
        Soa = apex.Single(record => record.Type == 6);
        foreach (var owner in all.Where(record => record.Type == 43).Select(record => record.Owner).Distinct())
        {
            if (owner.Equals(origin) || !GetRecords(owner).Any(record => record.Type == 2))
                throw new ArgumentException("DS data requires a parent-side delegation NS RRset.", nameof(records));
            for (var ancestor = owner.Parent; !ancestor.Equals(origin); ancestor = ancestor.Parent)
                if (GetRecords(ancestor).Any(record => record.Type == 2))
                    throw new ArgumentException("DS data cannot occur below an earlier delegation.", nameof(records));
        }
        foreach (var record in all.Where(record => record.Type == 39))
        {
            if (all.Any(other => !other.Owner.Equals(record.Owner) && other.Owner.IsSubdomainOf(record.Owner)))
                throw new ArgumentException("Data below a DNAME owner is not supported.", nameof(records));
        }
        if (all.Any(record => record.Type is 46 or 47 or 48 or 50 or 51))
            throw new ArgumentException("Signed zone data requires the future DNSSEC serving profile.", nameof(records));
    }

    public DnsName Origin { get; }
    public DnsRecord Soa { get; }
    public bool ContainsName(DnsName name) => names.Contains(name);
    public IReadOnlyList<DnsRecord> GetRecords(DnsName name) => records.TryGetValue(name, out var value) ? Array.AsReadOnly(value) : Array.Empty<DnsRecord>();
    public IReadOnlyList<DnsRecord> GetAllRecords() => Array.AsReadOnly(records.Values.SelectMany(items => items).ToArray());
}
