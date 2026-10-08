using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed class DnsRootPrimingResult
{
    private readonly DnssecResolutionClock clock;
    private readonly DnssecValidationLease lease;
    private readonly long received;
    private readonly uint lifetime;

    internal DnsRootPrimingResult(DnsName[] names, DnsRootRoutingHint[] hints, DnsServerEndpoint source, DnsName[] unresolved,
        DnssecResolutionClock clock, DnssecValidationLease lease, long received, uint lifetime)
    {
        NameServers = Array.AsReadOnly((DnsName[])names.Clone());
        RoutingHints = Array.AsReadOnly((DnsRootRoutingHint[])hints.Clone());
        UnresolvedNames = Array.AsReadOnly((DnsName[])unresolved.Clone());
        Source = source; this.clock = clock; this.lease = lease; this.received = received; this.lifetime = lifetime;
        AddressesAuthenticated = false;
    }

    public IReadOnlyList<DnsName> NameServers { get; }
    public IReadOnlyList<DnsRootRoutingHint> RoutingHints { get; }
    public IReadOnlyList<DnsName> UnresolvedNames { get; }
    public DnsServerEndpoint Source { get; }
    public uint RemainingTtl => !lease.IsValid() ? 0 : Math.Min(lease.Remaining(), clock.Age(lifetime, received, clock.GetTimestamp()));
    public bool AddressesAuthenticated { get; }
}
