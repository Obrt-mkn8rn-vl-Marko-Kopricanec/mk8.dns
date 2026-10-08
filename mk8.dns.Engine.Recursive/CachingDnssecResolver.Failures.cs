using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class CachingDnssecResolver
{
    private readonly Dictionary<DnsQuestion, LinkedListNode<FailureEntry>> failures = [];
    private readonly LinkedList<FailureEntry> recentFailures = new();
    private long failureBytes;
    private long failureHits;
    private long failureStores;
    private long failureEvictions;
    private long failureExpirations;
    private long failureAdmissionRejections;

    private bool ReadFailure(DnsQuestion question)
    {
        if (!failures.TryGetValue(question, out var node)) return false;
        var entry = node.Value;
        if (entry.Expired || resolver.Clock.GetElapsedTime(entry.Received, resolver.Clock.GetTimestamp()).TotalSeconds >= entry.Lifetime)
        {
            if (!entry.Expired) { entry.Expired = true; failureExpirations++; }
            return false; // Retain bounded history for the next failed retry, never extend it on a hit.
        }
        recentFailures.Remove(node); recentFailures.AddLast(node); failureHits++;
        return true;
    }

    private void StoreFailure(DnsQuestion question)
    {
        var policy = failurePolicy!;
        var lifetime = policy.MinimumTtl;
        if (failures.TryGetValue(question, out var previous))
        {
            if (!previous.Value.Expired) return;
            // Only a completed retry after expiry can increase hold-down.
            lifetime = Math.Min(policy.MaximumTtl, previous.Value.Lifetime * 2);
            RemoveFailure(previous);
        }
        var bytes = 64L + question.Name.ToWire().Length + 4;
        if (bytes > policy.MaximumPayloadBytes) { failureAdmissionRejections++; return; }
        while (failures.Count >= policy.MaximumEntries || failureBytes + bytes > policy.MaximumPayloadBytes)
        {
            RemoveFailure(recentFailures.First!); failureEvictions++;
        }
        var node = recentFailures.AddLast(new FailureEntry(question, resolver.Clock.GetTimestamp(), lifetime, bytes));
        failures.Add(question, node); failureBytes += bytes; failureStores++;
    }

    private void RemoveFailure(LinkedListNode<FailureEntry> node)
    {
        failures.Remove(node.Value.Question); recentFailures.Remove(node); failureBytes -= node.Value.Bytes;
    }

    private void ForgetFailure(DnsQuestion question)
    {
        if (failures.TryGetValue(question, out var node)) RemoveFailure(node);
    }

    private void ClearFailures()
    {
        failures.Clear(); recentFailures.Clear(); failureBytes = 0;
    }

    private sealed class FailureEntry(DnsQuestion question, long received, uint lifetime, long bytes)
    {
        internal DnsQuestion Question { get; } = question;
        internal long Received { get; } = received;
        internal uint Lifetime { get; } = lifetime;
        internal long Bytes { get; } = bytes;
        internal bool Expired { get; set; }
    }
}
