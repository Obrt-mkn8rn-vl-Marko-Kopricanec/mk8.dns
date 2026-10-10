using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

// Historical selected proof material, not a reusable security-state/AD authority.
// RRSIG arrays contain candidates for authenticated RRsets, not a claim that every candidate verified.
public sealed class DnssecResponseProof
{
    internal DnssecResponseProof(DnsRecord[] answerSignatures, DnsRecord[] authority, DnssecClientMaterialReceipt? receipt = null)
    {
        AnswerSignatures = Array.AsReadOnly((DnsRecord[])answerSignatures.Clone());
        Authority = Array.AsReadOnly((DnsRecord[])authority.Clone());
        Receipt = receipt;
    }

    public IReadOnlyList<DnsRecord> AnswerSignatures { get; }
    public IReadOnlyList<DnsRecord> Authority { get; }
    internal DnssecClientMaterialReceipt? Receipt { get; }
}
