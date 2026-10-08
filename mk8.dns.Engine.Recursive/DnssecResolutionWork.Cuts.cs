using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

internal sealed partial class DnssecResolutionWork
{
    private readonly Dictionary<DnsName, CutReceipt> cuts = [];

    internal bool RememberCut(DnssecResolutionProof boundary, DnssecResolutionProof? soa = null)
    {
        var name = boundary.Question.Name;
        var parent = boundary.Keys.Origin;
        var signed = boundary.Kind == DnssecResolutionProofKind.Exact;
        if (!Check(boundary.Question.Type == 43 && !name.Equals(parent) && name.IsSubdomainOf(parent)
            && (signed || boundary.Kind == DnssecResolutionProofKind.DsAbsence))) return false;
        if (cuts.TryGetValue(name, out var prior))
            return Check(prior.Boundary.Keys.Origin.Equals(parent) && prior.Signed == signed);
        // Each receipt requires a charged upstream DS exchange; the existing operation limits bound this table.
        cuts.Add(name, new CutReceipt(boundary, soa, signed));
        return true;
    }

    internal bool CrossesCut(DnsName current, DnsQuestion question, DnsName? next = null)
        => cuts.Keys.Any(cut => !cut.Equals(current) && cut.IsSubdomainOf(current) && question.Name.IsSubdomainOf(cut)
            && (next is null ? !(question.Type == 43 && question.Name.Equals(cut)) : !next.Equals(cut) && next.IsSubdomainOf(cut)));

    private IEnumerable<DnssecResolutionProof> CutProofs()
        => cuts.Values.SelectMany(receipt => receipt.Soa is null ? new[] { receipt.Boundary } : [receipt.Boundary, receipt.Soa]);

    private sealed record CutReceipt(DnssecResolutionProof Boundary, DnssecResolutionProof? Soa, bool Signed);
}
