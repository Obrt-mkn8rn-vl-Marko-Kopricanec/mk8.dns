using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Authoritative;

internal sealed class AuthorityResolution(DnsQuestion question, Func<DnsName, bool>? authorize, bool dnssecOk, uint now)
{
    internal DnsQuestion Question { get; } = question;
    internal Func<DnsName, bool>? Authorize { get; } = authorize;
    internal bool DnssecOk { get; } = dnssecOk;
    internal uint Now { get; } = now;
    internal List<DnsRecord> Answers { get; } = [];
    internal List<DnsRecord> Authority { get; } = [];
    internal HashSet<DnsName> Aliases { get; } = [];
    internal DnsAnswer Complete(byte code, bool authoritative, IEnumerable<DnsRecord>? additional = null)
        => new(code, authoritative, Answers, Authority, additional ?? []);
}
