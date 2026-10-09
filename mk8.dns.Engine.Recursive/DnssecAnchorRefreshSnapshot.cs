using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecAnchorRefreshSnapshot
{
    internal DnssecAnchorRefreshSnapshot(DnsName origin, long revision, IReadOnlyList<DnssecTrustAnchor> anchors)
    {
        Origin = origin;
        Revision = revision;
        Anchors = Array.AsReadOnly(anchors.ToArray());
    }

    public DnsName Origin { get; }
    public long Revision { get; }
    public IReadOnlyList<DnssecTrustAnchor> Anchors { get; }
}
