using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class CachingDnssecResolver
{
    private readonly bool retainClientProof;

    // The source and its coherent clock remain caller-owned. This does not attach a failure cache.
    public static CachingDnssecResolver CreateWithClientProofCache(DnssecIterativeResolver resolver,
        int maximumEntries = 4096, long maximumPayloadBytes = 16777216, int maximumRequests = 64,
        uint maximumPositiveTtl = 86400, uint maximumNegativeTtl = 3600)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        if (!resolver.CapturesClientProof)
            throw new ArgumentException("A client-proof cache requires the explicit proof-producing resolver.", nameof(resolver));
        return new CachingDnssecResolver(resolver, maximumEntries, maximumPayloadBytes, maximumRequests,
            maximumPositiveTtl, maximumNegativeTtl, retainClientProof: true);
    }

    private CachingDnssecResolver(DnssecIterativeResolver resolver, int maximumEntries, long maximumPayloadBytes,
        int maximumRequests, uint maximumPositiveTtl, uint maximumNegativeTtl, bool retainClientProof)
        : this(resolver, maximumEntries, maximumPayloadBytes, maximumRequests, maximumPositiveTtl, maximumNegativeTtl)
        => this.retainClientProof = retainClientProof;

    private DnssecResolutionResult PrepareClientProof(DnssecResolutionResult result)
    {
        if (result.AuthenticatedTtl == 0) return result;
        var negative = result.Authority.Count != 0 || result.ResponseCode == 3;
        return CaptureClientProof(result, negative ? maximumNegativeTtl : maximumPositiveTtl)
            ?? DnssecResolutionWork.Failure(result.Question);
    }

    private DnssecResolutionResult? ReadClientProof(DnsQuestion question)
    {
        if (!entries.TryGetValue(question, out var node)) return null;
        var entry = node.Value;
        var elapsed = Elapsed(entry.Received);
        var limit = elapsed >= entry.Lifetime ? 0 : entry.Lifetime - (uint)elapsed;
        var result = limit == 0 ? null : CaptureClientProof(entry.Result, limit);
        if (result is null)
        {
            Remove(node); expirations++; return null;
        }
        recent.Remove(node); recent.AddLast(node); hits++;
        return result;
    }

    private static DnssecResolutionResult? CaptureClientProof(DnssecResolutionResult result, uint limit)
    {
        if (!DnssecClientResponseProjection.TryPrepare(result, result.Question, dnssecOk: true, out var prepared)) return null;
        var lifetime = Math.Min(limit, prepared.RemainingTtl);
        if (lifetime == 0) return null;
        var answers = prepared.Answers.Select(record => record.WithTtl(Math.Min(lifetime, record.Ttl))).ToArray();
        var authority = prepared.Authority.Select(record => record.WithTtl(Math.Min(lifetime, record.Ttl))).ToArray();
        var receipt = result.ClientProof?.Receipt;
        if (receipt is null) return null;
        // Stamp before rechecking the ORIGINAL receipt, never before aging its material.
        // The original validation lease is retained, and hits never replace the stored entry.
        var (timestamp, wall) = receipt.Read();
        if (!DnssecClientResponseProjection.TryPrepare(result, result.Question, dnssecOk: true, out var current)
            || current.RemainingTtl < lifetime)
        {
            return null;
        }
        var proof = new DnssecResponseProof(answers[result.Answers.Count..], authority[result.Authority.Count..],
            new DnssecClientMaterialReceipt(receipt.Clock, timestamp, wall));
        return new DnssecResolutionResult(result.Question, result.Outcome, result.ResponseCode, result.Origin,
            result.UnsignedDelegation, lifetime, answers[..result.Answers.Count], authority[..result.Authority.Count], result.Lease, proof);
    }

    private long ClientProofBytes(DnssecResolutionResult result)
        // Fixed receipt charge is a serialized quota policy, not measured heap usage.
        => retainClientProof && result.ClientProof is { } proof
            ? 32L + proof.AnswerSignatures.Concat(proof.Authority).Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length)
            : 0;
}
