using System.Diagnostics.CodeAnalysis;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public sealed class DnssecUpstreamResponse
{
    internal DnssecUpstreamResponse(DnsUpstreamEvidence? evidence) => Evidence = evidence;
    public DnsUpstreamEvidence? Evidence { get; }
    [MemberNotNullWhen(false, nameof(Evidence))]
    public bool Truncated => Evidence is null;
}
