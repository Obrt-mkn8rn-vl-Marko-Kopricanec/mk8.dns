using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private static ResolutionStep? Dname(DnsQuestion question, AuthorityContext context, DnssecReceivedEvidence reply,
        DnsRecord[] records, DnssecResolutionWork work)
    {
        // Multiple ancestors imply occluded/ambiguous data; never choose using untrusted proximity.
        var owner = records[0].Owner;
        if (!owner.IsSubdomainOf(context.Keys.Origin) || !question.Name.IsSubdomainOf(context.Keys.Origin)
            || records.Any(record => !record.Owner.Equals(owner)) || records.Select(record => record.GetTarget()).Distinct().Count() != 1)
            return null;
        var dname = records[0].WithTtl(records.Min(record => record.Ttl));
        var atName = reply.Evidence.Answers.Where(record => record.Owner.Equals(question.Name)).ToArray();
        if (atName.Any(record => record.Type is not (5 or 46))) return null;
        var cnames = atName.Where(record => record.Type == 5).ToArray();
        var name = question.Name.ToWire();
        var prefix = name.Length - dname.GetOwnerWire().Length;
        var target = dname.GetData();
        DnsRecord? synthetic = null;
        DnsName? replacement = null;
        byte code = 0;
        if (prefix + target.Length > 255)
        {
            if (reply.Evidence.ResponseCode != 6 || cnames.Length != 0) return null;
            code = 6;
        }
        else
        {
            if (reply.Evidence.ResponseCode is not (0 or 3)) return null;
            replacement = DnsName.FromWire([.. name.AsSpan(0, prefix), .. target]);
            if (cnames.Any(record => !record.GetTarget().Equals(replacement))) return null;
            // Reconstruct locally; a supplied unsigned CNAME only constrains agreement and lifetime.
            var ttl = cnames.Length == 0 ? dname.Ttl : Math.Min(dname.Ttl, cnames.Min(record => record.Ttl));
            synthetic = new DnsRecord(question.Name, 5, ttl, replacement.ToWire());
        }
        var signatures = Signatures(reply.Evidence.Answers, [dname]);
        return DnssecResolutionProof.TryCreate(DnssecResolutionProofKind.Exact, context.Keys, new DnsQuestion(owner, 39, 1),
            [dname], [], [], signatures, reply.Received, out var proof, synthetic) && proof.Authenticate(work.Validator, work.Clock)
            ? new ResolutionStep(proof, code, question.Type == 5 ? null : replacement) : null;
    }
}
