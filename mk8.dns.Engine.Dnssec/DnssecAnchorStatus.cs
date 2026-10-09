using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed class DnssecAnchorStatus
{
    internal DnssecAnchorStatus(DnsRecord key, DnssecAnchorState state, TimeSpan remaining)
    {
        Key = key;
        State = state;
        AddHoldDownRemaining = remaining;
    }

    public DnsRecord Key { get; }
    public DnssecAnchorState State { get; }
    public TimeSpan AddHoldDownRemaining { get; }
}
