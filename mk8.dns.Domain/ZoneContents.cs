namespace Mk8.Dns.Domain;

public sealed class ZoneContents
{
    public const int MaximumRecords = 40_002;
    private readonly DnsRecord[] security;

    public ZoneContents(AuthoritativeZone source) : this(source, []) { }

    public ZoneContents(AuthoritativeZone source, IEnumerable<DnsRecord> securityRecords)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(securityRecords);
        Source = source;
        security = securityRecords.Take(MaximumRecords + 1).ToArray();
        var original = source.GetAllRecords();
        if (security.Length > MaximumRecords - original.Count
            || security.Any(record => record.Type is not (46 or 47 or 48) || !record.Owner.IsSubdomainOf(source.Origin))
            || original.Concat(security).Sum(record => (long)record.GetOwnerWire().Length + 8 + record.GetData().Length) > ZoneSnapshot.MaximumPayloadBytes - 6)
            throw new ArgumentException("Signed bundle content exceeds its structural bounds.", nameof(securityRecords));
    }

    public AuthoritativeZone Source { get; }
    public bool IsSigned => security.Length != 0;
    public IReadOnlyList<DnsRecord> GetSecurityRecords() => Array.AsReadOnly(security);
    public IReadOnlyList<DnsRecord> GetAllRecords() => Array.AsReadOnly(Source.GetAllRecords().Concat(security).ToArray());
}
