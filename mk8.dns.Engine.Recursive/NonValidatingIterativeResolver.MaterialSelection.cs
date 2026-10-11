using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class NonValidatingIterativeResolver
{
    private Step? AnalyzeStep(DnsQuestion question, DnsName cut, DnsAnswer reply)
    {
        var step = AnalyzeAuthoritative(question, cut, reply);
        return captureDnssecMaterial && step is not null ? CaptureMaterial(question, cut, reply, step) : step;
    }

    private void AppendStep(List<(DnsRecord Record, long Received)> chain,
        List<(DnsRecord Record, long Received)> materialAuthority, Step step, long received)
    {
        chain.AddRange(step.Answer.Answers.Select(record => (record, received)));
        if (captureDnssecMaterial)
            materialAuthority.AddRange(step.Answer.Authority.Select(record => (record, received)));
    }

    private DnsAnswer FinishAnswer(List<(DnsRecord Record, long Received)> chain,
        List<(DnsRecord Record, long Received)> materialAuthority, DnsAnswer terminal)
    {
        var answer = new DnsAnswer(terminal.ResponseCode, authoritative: false, AgeChain(chain).Concat(terminal.Answers),
            captureDnssecMaterial ? AgeChain(materialAuthority).Concat(terminal.Authority) : terminal.Authority, []);
        return captureDnssecMaterial && !FitsMaterial(answer) ? Empty(2) : answer;
    }

    private static Step CaptureMaterial(DnsQuestion question, DnsName cut, DnsAnswer reply, Step step)
    {
        // Select only from this accepted authoritative step, never from routing or address dependencies.
        // These are unverified candidate bytes; observed flags, signer names and signature windows confer no trust.
        var dname = step.Answer.Answers.Any(record => record.Type == 39 && !record.Owner.Equals(question.Name));
        var covered = step.Answer.Answers.Where(record => !dname || record.Type != 5).ToArray();
        var signatures = reply.Answers.Where(record => Covers(record, covered)).ToArray();
        var wildcard = signatures.Any(record => record.GetData() is { Length: >= 4 } data && data[3] < record.Owner.LabelCount);
        var denial = step.Answer.Authority.Any(record => record.Type == 6) || wildcard
            ? reply.Authority.Where(record => record.Type is 47 or 50 && record.Owner.IsSubdomainOf(cut)).ToArray() : [];
        var authority = step.Answer.Authority.Concat(denial).ToArray();
        var authoritySignatures = reply.Authority.Where(record => Covers(record, authority));
        return new Step(new DnsAnswer(step.Answer.ResponseCode, authoritative: false,
            step.Answer.Answers.Concat(signatures), authority.Concat(authoritySignatures), []), step.Target);
    }

    private static bool Covers(DnsRecord candidate, IReadOnlyList<DnsRecord> records)
    {
        if (candidate.Type != 46 || candidate.GetData() is not { Length: >= 2 } data)
            return false;
        var type = BinaryPrimitives.ReadUInt16BigEndian(data);
        return records.Any(record => record.Type == type && record.Owner.Equals(candidate.Owner));
    }
}
