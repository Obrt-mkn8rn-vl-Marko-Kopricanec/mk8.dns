using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

// Historical preparation only. Prepare again at delivery; this carries no AD/CD authority.
public sealed class DnssecClientResponseSnapshot
{
    internal DnssecClientResponseSnapshot(DnsQuestion question, byte responseCode, DnsName origin, bool dnssecOk,
        uint remainingTtl, DnsRecord[] answers, DnsRecord[] authority)
    {
        Question = question;
        ResponseCode = responseCode;
        Origin = origin;
        DnssecOk = dnssecOk;
        RemainingTtl = remainingTtl;
        Answers = Array.AsReadOnly((DnsRecord[])answers.Clone());
        Authority = Array.AsReadOnly((DnsRecord[])authority.Clone());
    }

    public DnsQuestion Question { get; }
    public byte ResponseCode { get; }
    public DnsName Origin { get; }
    public bool DnssecOk { get; }
    public uint RemainingTtl { get; }
    public IReadOnlyList<DnsRecord> Answers { get; }
    public IReadOnlyList<DnsRecord> Authority { get; }
}
