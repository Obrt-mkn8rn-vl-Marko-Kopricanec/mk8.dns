using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed class DnsRootRoutingHint
{
    internal DnsRootRoutingHint(DnsName name, DnsServerEndpoint server, DnsRootHintSource source)
    {
        Name = name; Server = server; Source = source;
    }
    public DnsName Name { get; }
    public DnsServerEndpoint Server { get; }
    public DnsRootHintSource Source { get; }
}
