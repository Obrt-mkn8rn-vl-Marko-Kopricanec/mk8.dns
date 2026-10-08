using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecResolutionResult
{
    internal DnssecResolutionResult(DnsQuestion question, DnssecResolutionOutcome outcome, byte responseCode,
        DnsName? origin, DnsName? unsignedDelegation, uint authenticatedTtl, DnsRecord[] answers, DnsRecord[] authority,
        DnssecValidationLease? lease = null)
    {
        Question = question;
        Outcome = outcome;
        ResponseCode = responseCode;
        Origin = origin;
        UnsignedDelegation = unsignedDelegation;
        AuthenticatedTtl = authenticatedTtl;
        Answers = Array.AsReadOnly((DnsRecord[])answers.Clone());
        Authority = Array.AsReadOnly((DnsRecord[])authority.Clone());
        Lease = lease;
    }

    public DnsQuestion Question { get; }
    public DnssecResolutionOutcome Outcome { get; }
    public byte ResponseCode { get; }
    public DnsName? Origin { get; }
    public DnsName? UnsignedDelegation { get; }
    public uint AuthenticatedTtl { get; }
    public IReadOnlyList<DnsRecord> Answers { get; }
    public IReadOnlyList<DnsRecord> Authority { get; }
    internal DnssecValidationLease? Lease { get; }
}
