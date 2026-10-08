using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private async ValueTask<DnssecResolutionResult> ResolveQuestionAsync(DnsQuestion original, AuthorityContext bootstrap,
        DnssecResolutionWork work, CancellationToken cancellationToken)
    {
        var question = original;
        HashSet<DnsName> seen = [question.Name];
        while (Supported(question) && !work.Exhausted)
        {
            var choice = await SearchAsync(question, bootstrap, work, cancellationToken).ConfigureAwait(false);
            if (choice is null) break;
            if (choice.Unsigned is not null) return work.Finish(original, 2, choice.Origin, choice.Unsigned);
            var step = choice.Step!;
            work.Proofs.Add(step.Proof);
            if (step.Target is null) return work.Finish(original, step.Code, choice.Origin);
            if (!work.TakeAlias() || !seen.Add(step.Target)) return DnssecResolutionWork.Failure(original);
            question = question with { Name = step.Target }; // Authenticated aliases restart at the static anchor.
        }
        return DnssecResolutionWork.Failure(original);
    }

    private static ResolutionStep? Terminal(DnsQuestion question, AuthorityContext context, DnssecReceivedEvidence reply, DnssecResolutionWork work)
    {
        var dnames = reply.Evidence.Answers.Where(record => record.Type == 39 && !record.Owner.Equals(question.Name)
            && question.Name.IsSubdomainOf(record.Owner)).ToArray();
        if (dnames.Length != 0) return Dname(question, context, reply, dnames, work);
        if (reply.Evidence.ResponseCode == 6) return null;
        var atName = reply.Evidence.Answers.Where(record => record.Owner.Equals(question.Name)).ToArray();
        var cnames = atName.Where(record => record.Type == 5).ToArray();
        if (cnames.Length != 0)
        {
            if (atName.Any(record => record.Type is not (5 or 46)) || cnames.Select(record => record.GetTarget()).Distinct().Count() != 1)
                return null;
            var proof = Positive(question with { Type = 5 }, context, reply, cnames, work);
            return proof is null ? null : new ResolutionStep(proof, 0, question.Type == 5 ? null : cnames[0].GetTarget());
        }
        var records = atName.Where(record => record.Type == question.Type).ToArray();
        if (records.Length != 0)
        {
            if (reply.Evidence.ResponseCode != 0 || question.Type == 6 && !question.Name.Equals(context.Keys.Origin)) return null;
            var proof = Positive(question, context, reply, records, work);
            return proof is null ? null : new ResolutionStep(proof, 0, null);
        }
        return Negative(question, context, reply, work);
    }

    private static DnssecResolutionProof? Positive(DnsQuestion question, AuthorityContext context, DnssecReceivedEvidence reply,
        DnsRecord[] records, DnssecResolutionWork work)
    {
        var signatures = Signatures(reply.Evidence.Answers, records);
        if (DnssecResolutionProof.TryCreate(DnssecResolutionProofKind.Exact, context.Keys, question, records, [], [], signatures,
            reply.Received, out var exact) && exact.Authenticate(work.Validator, work.Clock)) return exact;
        var nsecs = reply.Evidence.Authority.Where(record => record.Type is 47 or 50).ToArray();
        signatures = [.. signatures, .. Signatures(reply.Evidence.Authority, nsecs)];
        return DnssecResolutionProof.TryCreate(DnssecResolutionProofKind.Wildcard, context.Keys, question, records, [], nsecs,
            signatures, reply.Received, out var wildcard) && wildcard.Authenticate(work.Validator, work.Clock) ? wildcard : null;
    }

    private static ResolutionStep? Negative(DnsQuestion question, AuthorityContext context, DnssecReceivedEvidence reply, DnssecResolutionWork work)
    {
        if (reply.Evidence.Answers.Count != 0) return null;
        var soa = Rrset(reply.Evidence.Authority, context.Keys.Origin, 6);
        if (soa.Length != 1) return null;
        var nsecs = reply.Evidence.Authority.Where(record => record.Type is 47 or 50).ToArray();
        var signatures = Signatures(reply.Evidence.Authority, soa, nsecs);
        var kind = reply.Evidence.ResponseCode == 3 ? DnssecResolutionProofKind.NameError : DnssecResolutionProofKind.NoData;
        return DnssecResolutionProof.TryCreate(kind, context.Keys, question, [], soa, nsecs, signatures, reply.Received, out var proof)
            && proof.Authenticate(work.Validator, work.Clock) ? new ResolutionStep(proof, (byte)reply.Evidence.ResponseCode, null) : null;
    }
}
