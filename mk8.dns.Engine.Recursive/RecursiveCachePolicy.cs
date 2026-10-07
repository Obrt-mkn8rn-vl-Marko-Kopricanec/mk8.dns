using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

internal sealed class RecursiveCachePolicy(uint positiveTtl, uint negativeTtl)
{
    internal static bool Supports(DnsQuestion question) => question.Class == 1 && question.Type is not (0 or 41 or (>= 249 and <= 255));

    internal static bool ProvesNameExists(DnsQuestion question, DnsAnswer answer)
    {
        if (answer.ResponseCode is not (0 or 3)) return false;
        var terminal = TerminalName(question, answer);
        return answer.Answers.Any(record => record.Type == 5 && record.Owner.Equals(question.Name))
            || answer.ResponseCode == 0 && answer.Answers.Any(record => record.Type == question.Type && record.Owner.Equals(terminal));
    }

    internal RecursiveCacheCandidate? Prepare(DnsQuestion question, DnsAnswer answer)
    {
        if (answer.Authoritative || answer.Additional.Count != 0)
            throw new InvalidOperationException("A recursive provider returned an unselected or authoritative answer.");
        if (answer.ResponseCode is not (0 or 3) || answer.Answers.Count + answer.Authority.Count is 0 or > 512)
            return null;
        var terminal = TerminalName(question, answer);
        var positive = answer.ResponseCode == 0 && answer.Answers.Any(record => record.Owner.Equals(terminal) && record.Type == question.Type);
        var negative = !positive && answer.Authority.Count == 1 && answer.Authority[0].Type == 6
            && terminal.IsSubdomainOf(answer.Authority[0].Owner) && answer.Answers.All(record => record.Type is 5 or 39);
        if (!positive && !negative || positive && answer.Authority.Count != 0)
            return null;
        var answers = Normalize(answer.Answers, positiveTtl);
        var authority = negative ? new[] { answer.Authority[0].WithTtl(Math.Min(negativeTtl, Math.Min(answer.Authority[0].Ttl, answer.Authority[0].GetSoaMinimum()))) } : Array.Empty<DnsRecord>();
        var prepared = new DnsAnswer(answer.ResponseCode, false, answers, authority, []);
        var records = prepared.Answers.Concat(prepared.Authority).ToArray();
        var lifetime = records.Min(record => record.Ttl);
        var size = question.Name.ToWire().Length + 16L + records.Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length);
        // Whole-answer storage is deliberately more conservative than a shared RRset cache.
        var nameWide = answer.ResponseCode == 3 && answer.Answers.Count == 0;
        return new RecursiveCacheCandidate(prepared, nameWide, lifetime, size);
    }

    private static DnsName TerminalName(DnsQuestion question, DnsAnswer answer)
    {
        var name = question.Name;
        if (question.Type != 5)
            foreach (var record in answer.Answers)
                if (record.Type == 5 && record.Owner.Equals(name))
                    name = record.GetTarget();
        return name;
    }

    private static DnsRecord[] Normalize(IReadOnlyList<DnsRecord> records, uint maximumTtl)
    {
        var ttls = records.GroupBy(record => (record.Owner, record.Type)).ToDictionary(group => group.Key, group => Math.Min(maximumTtl, group.Min(record => record.Ttl)));
        return records.Select(record => record.WithTtl(ttls[(record.Owner, record.Type)])).ToArray();
    }
}
