using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class CachingDnssecResolver
{
    private DnssecResolutionResult Prepare(DnssecResolutionResult result)
    {
        var negative = result.Authority.Count != 0 || result.ResponseCode == 3;
        var limit = negative ? maximumNegativeTtl : maximumPositiveTtl;
        var lifetime = Math.Min(limit, result.Lease!.Remaining());
        return Copy(result, lifetime, Normalize(result.Answers, lifetime), Normalize(result.Authority, lifetime));
    }

    private DnssecResolutionResult? Read(DnsQuestion question)
    {
        if (!entries.TryGetValue(question, out var node)) return null;
        var entry = node.Value;
        var elapsed = Elapsed(entry.Received);
        var lifetime = elapsed >= entry.Lifetime ? 0 : entry.Lifetime - (uint)elapsed;
        lifetime = Math.Min(lifetime, entry.Result.Lease!.Remaining());
        if (lifetime == 0 || !entry.Result.Lease.IsValid())
        {
            Remove(node); expirations++; return null;
        }
        recent.Remove(node); recent.AddLast(node); hits++;
        return Copy(entry.Result, lifetime, Age(entry.Result.Answers, elapsed, lifetime), Age(entry.Result.Authority, elapsed, lifetime));
    }

    private void Store(DnssecResolutionResult result)
    {
        if (result.ResponseCode is not (0 or 3)) return;
        var identity = (result.Question.Name, result.Question.Class);
        var state = names[identity];
        var absence = result.ResponseCode == 3 && result.Answers.Count == 0;
        foreach (var question in state.Questions.ToArray())
        {
            var previous = entries[question].Value.Result;
            var previousAbsence = previous.ResponseCode == 3 && previous.Answers.Count == 0;
            if (absence || previousAbsence || question.Equals(result.Question)) Remove(entries[question]);
        }
        var bytes = 64L + result.Question.Name.ToWire().Length + 4L
            + (result.Origin?.ToWire().Length ?? 0)
            + result.Answers.Concat(result.Authority).Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length);
        if (result.AuthenticatedTtl == 0 || bytes > maximumPayloadBytes || bytes > DnsUpstreamEvidence.MaximumExpandedBytes)
            return;
        var stamp = resolver.Clock.GetTimestamp();
        if (!result.Lease!.IsValid() || result.Lease.Remaining() == 0) return;
        while (entries.Count >= maximumEntries || payloadBytes + bytes > maximumPayloadBytes)
        {
            Remove(recent.First!); evictions++;
        }
        var lifetime = Math.Min(result.AuthenticatedTtl, result.Lease.Remaining());
        if (lifetime == 0) return;
        var node = recent.AddLast(new Entry(result, stamp, lifetime, bytes));
        entries.Add(result.Question, node); state.Questions.Add(result.Question); payloadBytes += bytes;
    }

    private void Remove(LinkedListNode<Entry> node)
    {
        var entry = node.Value; entries.Remove(entry.Result.Question); recent.Remove(node); payloadBytes -= entry.Bytes;
        var identity = (entry.Result.Question.Name, entry.Result.Question.Class); var state = names[identity];
        state.Questions.Remove(entry.Result.Question); DropName(identity, state);
    }

    private void DropName((DnsName Name, ushort Class) identity, NameState state)
    {
        if (state.Active == 0 && state.Questions.Count == 0) names.Remove(identity);
    }

    private double Elapsed(long received) => Math.Ceiling(Math.Max(0, resolver.Clock.GetElapsedTime(received, resolver.Clock.GetTimestamp()).TotalSeconds));

    private static DnsRecord[] Normalize(IReadOnlyList<DnsRecord> records, uint lifetime)
    {
        var ttl = records.GroupBy(record => (record.Owner, record.Type)).ToDictionary(group => group.Key, group => group.Min(record => record.Ttl));
        return records.Select(record => record.WithTtl(Math.Min(lifetime, ttl[(record.Owner, record.Type)]))).ToArray();
    }
    private static DnsRecord[] Age(IReadOnlyList<DnsRecord> records, double elapsed, uint lifetime)
        => records.Select(record => record.WithTtl(Math.Min(lifetime, elapsed >= record.Ttl ? 0 : record.Ttl - (uint)elapsed))).ToArray();

    private static DnssecResolutionResult Copy(DnssecResolutionResult result, uint lifetime, DnsRecord[] answers, DnsRecord[] authority)
        => new(result.Question, result.Outcome, result.ResponseCode, result.Origin, result.UnsignedDelegation, lifetime, answers, authority, result.Lease);
}
