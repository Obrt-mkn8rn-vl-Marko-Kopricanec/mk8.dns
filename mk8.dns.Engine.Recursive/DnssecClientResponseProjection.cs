using System.Diagnostics.CodeAnalysis;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public static class DnssecClientResponseProjection
{
    // Requires the explicit proof-producing source. False never classifies data as insecure.
    public static bool TryPrepare(DnssecResolutionResult result, DnsQuestion expected, bool dnssecOk,
        [NotNullWhen(true)] out DnssecClientResponseSnapshot? snapshot)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(expected);
        snapshot = null;
        var material = result.ClientProof;
        var receipt = material?.Receipt;
        var lease = result.Lease;
        if (!result.Question.Equals(expected) || result.Outcome != DnssecResolutionOutcome.Authenticated
            || result.ResponseCode is not (0 or 3 or 6) || result.Origin is null || material is null || receipt is null
            || lease?.UsesClock(receipt.Clock) != true)
        {
            return false;
        }

        var answers = Select(result.Answers, material.AnswerSignatures, expected.Type, dnssecOk);
        var authority = Select(result.Authority, material.Authority, expected.Type, dnssecOk);
        DnsRecord[] selected = [.. answers, .. authority];
        if (selected.Length is 0 or > DnsUpstreamEvidence.MaximumRecords
            || selected.Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length) > DnsUpstreamEvidence.MaximumExpandedBytes)
        {
            return false;
        }
        var stamp = receipt.Read();
        var lifetime = Math.Min(lease.RemainingAt(stamp), Math.Min(receipt.Age(result.AuthenticatedTtl, stamp),
            selected.Min(record => receipt.Age(record.Ttl, stamp))));
        if (lifetime == 0) return false;
        var prepared = new DnssecClientResponseSnapshot(expected, result.ResponseCode, result.Origin, dnssecOk, lifetime,
            [.. answers.Select(record => receipt.Age(record, stamp, lifetime))],
            [.. authority.Select(record => receipt.Age(record, stamp, lifetime))]);
        var final = receipt.Read();
        if (lease.RemainingAt(final) < lifetime || receipt.Age(result.AuthenticatedTtl, final) < lifetime
            || selected.Any(record => receipt.Age(record.Ttl, final) < lifetime))
        {
            return false;
        }
        snapshot = prepared;
        return true;
    }

    private static DnsRecord[] Select(IReadOnlyList<DnsRecord> ordinary, IReadOnlyList<DnsRecord> proof, ushort requested, bool dnssecOk)
        => dnssecOk ? [.. ordinary, .. proof] : [.. ordinary.Where(record => !IsDnssec(record.Type) || record.Type == requested)];

    private static bool IsDnssec(ushort type) => type is 43 or 46 or 47 or 48 or 50 or 51;
}
