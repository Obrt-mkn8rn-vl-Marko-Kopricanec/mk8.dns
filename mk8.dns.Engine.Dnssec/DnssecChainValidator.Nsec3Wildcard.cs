using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed partial class DnssecChainValidator
{
    public bool TryAuthenticateNsec3Wildcard(AuthenticatedDnskeySet keys, DnsQuestion question, IReadOnlyList<DnsRecord> records,
        IReadOnlyList<DnsRecord> nsec3s, IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(nsec3s);
        ArgumentNullException.ThrowIfNull(signatures);
        authenticatedTtl = 0;
        var stamp = ReadClock();
        if (!AdmitQuestion(keys, question, stamp) || question.Type is 2 or 6 or 43 or 46 or 47 or 48 or 50 or 51
            || !DnssecValidationInput.TryRrset(records, question.Name, question.Type, MaximumRrsetRecords, out var items)
            || !TryNsec3Inputs(keys.Origin, nsec3s, signatures, out var denial, out var sigs)) return false;
        var budget = new Budget();
        if (!AuthenticateNsec3s(keys, denial, sigs, stamp, budget, out var proofs) || denial.Blocks(question, keys.Origin)
            || denial.Match(question.Name) is not null) return false;
        foreach (var signature in sigs)
        {
            RrsigData data;
            try { data = RrsigData.Decode(signature); }
            catch (Exception error) when (error is ArgumentException or FormatException) { continue; }
            if (!signature.Owner.Equals(question.Name) || data.Type != question.Type
                || data.Labels < keys.Origin.LabelCount || data.Labels >= question.Name.LabelCount) continue;
            var closest = question.Name;
            while (closest.LabelCount > data.Labels) closest = closest.Parent;
            // Wildcard data authenticates its own closest encloser. RFC 5155
            // does not require a matching NSEC3 for that encloser in this case.
            if (denial.Cover(NextCloser(question.Name, closest)) is not { OptOut: false }) continue;
            var wildcard = closest.PrependLabel([(byte)'*']);
            if (denial.Cover(wildcard) is not null) continue;
            var source = denial.Match(wildcard);
            if (source is not null && (source.Delegation || !source.Types.Contains(question.Type)
                || source.Types.Contains((ushort)5) && question.Type != 5)) continue;
            if (!TryVerifyResponse(items, [signature], keys, stamp, budget, data.Labels, out var proof)) continue;
            proofs.Add(proof);
            return FinishResponse(keys, stamp, proofs, uint.MaxValue, out authenticatedTtl);
        }
        return false;
    }
}
