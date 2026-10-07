using System.Diagnostics.CodeAnalysis;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed partial class DnssecChainValidator
{
    public const int MaximumNsecRecords = 8;

    // The caller selects the actual containing zone and complete, already-aged
    // proof RRsets. These methods do not discover cuts or set response AD/status.
    public bool TryAuthenticateNameError(AuthenticatedDnskeySet keys, DnsQuestion question, IReadOnlyList<DnsRecord> soa,
        IReadOnlyList<DnsRecord> nsecs, IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl)
        => TryAuthenticateNegative(keys, question, soa, nsecs, signatures, nameError: true, out authenticatedTtl);

    public bool TryAuthenticateNoData(AuthenticatedDnskeySet keys, DnsQuestion question, IReadOnlyList<DnsRecord> soa,
        IReadOnlyList<DnsRecord> nsecs, IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl)
        => TryAuthenticateNegative(keys, question, soa, nsecs, signatures, nameError: false, out authenticatedTtl);

    public bool TryAuthenticateDsAbsence(AuthenticatedDnskeySet parent, DnsName child, IReadOnlyList<DnsRecord> nsecs,
        IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl)
    {
        ArgumentNullException.ThrowIfNull(parent);
        ArgumentNullException.ThrowIfNull(child);
        ArgumentNullException.ThrowIfNull(nsecs);
        ArgumentNullException.ThrowIfNull(signatures);
        authenticatedTtl = 0;
        var question = new DnsQuestion(child, 43, 1);
        var stamp = ReadClock();
        if (!AdmitQuestion(parent, question, stamp) || child.Equals(parent.Origin)
            || !TryProofInputs(parent.Origin, nsecs, signatures, out var denial, out var sigs))
            return false;
        var budget = new Budget();
        if (!AuthenticateNsecs(parent, denial, sigs, stamp, budget, out var proofs) || denial.Any(item => item.Blocks(question)))
            return false;
        var exact = denial.SingleOrDefault(item => item.Owner.Equals(child));
        return exact is { Delegation: true } && exact.Lacks(43) && !exact.Types.Contains((ushort)6)
            && FinishResponse(parent, stamp, proofs, uint.MaxValue, out authenticatedTtl);
    }

    public bool TryAuthenticateWildcard(AuthenticatedDnskeySet keys, DnsQuestion question, IReadOnlyList<DnsRecord> records,
        IReadOnlyList<DnsRecord> nsecs, IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(nsecs);
        ArgumentNullException.ThrowIfNull(signatures);
        authenticatedTtl = 0;
        var stamp = ReadClock();
        if (!AdmitQuestion(keys, question, stamp) || question.Type is 2 or 6 or 43 or 46 or 47 or 48
            || !DnssecValidationInput.TryRrset(records, question.Name, question.Type, MaximumRrsetRecords, out var items)
            || !TryProofInputs(keys.Origin, nsecs, signatures, out var denial, out var sigs))
            return false;
        var budget = new Budget();
        if (!AuthenticateNsecs(keys, denial, sigs, stamp, budget, out var proofs) || denial.Any(item => item.Blocks(question))
            || !ProvesAbsent(denial, question.Name))
            return false;
        var closest = Closest(keys.Origin, question.Name, denial);
        var wildcard = closest.PrependLabel([(byte)'*']);
        var nextCloser = NextCloser(question.Name, closest);
        if (!ProvesAbsent(denial, nextCloser)
            || !TryVerifyResponse(items, sigs, keys, stamp, budget, (byte)closest.LabelCount, out var proof))
            return false;
        var source = denial.SingleOrDefault(item => item.Owner.Equals(wildcard));
        if (source is not null && (source.Delegation || !source.Types.Contains(question.Type)
            || source.Types.Contains((ushort)5) && question.Type != 5))
            return false;
        proofs.Add(proof);
        return FinishResponse(keys, stamp, proofs, uint.MaxValue, out authenticatedTtl);
    }

    private bool TryAuthenticateNegative(AuthenticatedDnskeySet keys, DnsQuestion question, IReadOnlyList<DnsRecord> soa,
        IReadOnlyList<DnsRecord> nsecs, IReadOnlyList<DnsRecord> signatures, bool nameError, out uint ttl)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(soa);
        ArgumentNullException.ThrowIfNull(nsecs);
        ArgumentNullException.ThrowIfNull(signatures);
        ttl = 0;
        var stamp = ReadClock();
        if (!AdmitQuestion(keys, question, stamp) || question.Type == 43 && question.Name.Equals(keys.Origin)
            || !nameError && question.Name.Equals(keys.Origin) && question.Type is 6 or 48
            || !DnssecValidationInput.TryRrset(soa, keys.Origin, 6, 1, out var soaRecords)
            || !TryProofInputs(keys.Origin, nsecs, signatures, out var denial, out var sigs))
            return false;
        var budget = new Budget();
        if (!TryVerifyResponse(soaRecords, sigs, keys, stamp, budget, (byte)keys.Origin.LabelCount, out var soaProof)
            || !AuthenticateNsecs(keys, denial, sigs, stamp, budget, out var proofs) || denial.Any(item => item.Blocks(question)))
            return false;
        proofs.Add(soaProof);
        if (nameError ? !ProvesNameError(keys.Origin, question, denial) : !ProvesNoData(keys.Origin, question, denial))
            return false;
        return FinishResponse(keys, stamp, proofs, soaRecords[0].GetSoaMinimum(), out ttl);
    }

    private bool AdmitQuestion(AuthenticatedDnskeySet keys, DnsQuestion question, Stamp stamp)
        => Remaining(keys, stamp) != 0 && question.Name is not null && question.Class == 1
            && question.Type is not (0 or 41 or >= 249 and <= 255) && question.Name.IsSubdomainOf(keys.Origin)
            && !DnssecData.IsWildcard(question.Name);

    private static bool TryProofInputs(DnsName origin, IReadOnlyList<DnsRecord> input, IReadOnlyList<DnsRecord> signatures,
        out NsecProof[] denial, out DnsRecord[] sigs)
    {
        denial = [];
        sigs = [];
        if (input.Count is 0 or > MaximumNsecRecords || !DnssecValidationInput.TrySignatures(signatures, out sigs))
            return false;
        var snapshot = input.ToArray();
        if (snapshot.Length != input.Count || snapshot.Any(record => record is null || record.Type != 47)
            || snapshot.Select(record => record.Owner).Distinct().Count() != snapshot.Length)
            return false;
        try
        {
            var decoded = snapshot.Select(record => NsecProof.Decode(record, origin)).ToArray();
            denial = decoded;
            // Endpoints assert existence. Reject mutually contradictory intervals,
            // including a claimed one-node ring accompanied by another node.
            return !decoded.Any(item => decoded.Any(other => item.Covers(other.Owner) || item.Covers(other.Next)));
        }
        catch (FormatException) { return false; }
    }

    private bool AuthenticateNsecs(AuthenticatedDnskeySet keys, NsecProof[] denial, DnsRecord[] sigs, Stamp stamp,
        Budget budget, out List<Proof> proofs)
    {
        proofs = new List<Proof>(denial.Length + 1);
        foreach (var item in denial)
        {
            var labels = item.Owner.LabelCount - (DnssecData.IsWildcard(item.Owner) ? 1 : 0);
            if (!TryVerifyResponse([item.Record], sigs, keys, stamp, budget, (byte)labels, out var proof))
                return false;
            proofs.Add(proof);
        }
        return true;
    }

    private bool TryVerifyResponse(DnsRecord[] records, DnsRecord[] sigs, AuthenticatedDnskeySet keys, Stamp stamp,
        Budget budget, byte labels, [NotNullWhen(true)] out Proof? proof)
    {
        proof = null;
        foreach (var signature in sigs)
        {
            RrsigData data;
            try { data = RrsigData.Decode(signature); }
            catch (Exception error) when (error is FormatException or ArgumentException) { continue; }
            if (!signature.Owner.Equals(records[0].Owner) || data.Type != records[0].Type || data.Labels != labels)
                continue;
            foreach (var key in keys.UsableKeys)
            {
                if (!data.Signer.Equals(key.Owner) || data.KeyTag != DnssecKeys.KeyTag(key))
                    continue;
                if (!budget.Take())
                    return false;
                if (DnssecRrsetVerifier.TryVerify(records, signature, key, stamp.Now, verifier, out var ttl))
                {
                    proof = new Proof(data.Window, ttl);
                    return true;
                }
            }
        }
        return false;
    }

    private bool FinishResponse(AuthenticatedDnskeySet keys, Stamp received, IReadOnlyList<Proof> proofs, uint cap, out uint ttl)
    {
        ttl = 0;
        var final = ReadClock();
        var remainingKeys = Remaining(keys, final);
        if (remainingKeys == 0 || proofs.Any(proof => !proof.Window.Contains(final.Now)))
            return false;
        ttl = Math.Min(remainingKeys, Age(Math.Min(cap, proofs.Min(proof => proof.Ttl)), received.Received, final.Received));
        foreach (var proof in proofs)
            ttl = Math.Min(ttl, unchecked(proof.Window.Expiration - final.Now));
        return true;
    }

    private static bool ProvesNameError(DnsName origin, DnsQuestion question, NsecProof[] denial)
    {
        if (!ProvesAbsent(denial, question.Name))
            return false;
        var closest = Closest(origin, question.Name, denial);
        return ProvesAbsent(denial, NextCloser(question.Name, closest))
            && ProvesAbsent(denial, closest.PrependLabel([(byte)'*']));
    }

    private static bool ProvesNoData(DnsName origin, DnsQuestion question, NsecProof[] denial)
    {
        var exact = denial.SingleOrDefault(item => item.Owner.Equals(question.Name));
        if (exact is not null)
            return exact.Lacks(question.Type);
        if (ProvesEmptyNonterminal(denial, question.Name))
            return true; // Existing empty nonterminal; wildcard expansion is inapplicable.
        if (question.Type == 43 || !ProvesAbsent(denial, question.Name))
            return false;
        var closest = Closest(origin, question.Name, denial);
        var wildcard = closest.PrependLabel([(byte)'*']);
        return ProvesAbsent(denial, NextCloser(question.Name, closest))
            && (denial.Any(item => item.Owner.Equals(wildcard) && item.Lacks(question.Type))
                || ProvesEmptyNonterminal(denial, wildcard));
    }

    private static bool ProvesEmptyNonterminal(NsecProof[] denial, DnsName name)
        => denial.Any(item => item.Covers(name) && item.Next.IsSubdomainOf(name));

    private static bool ProvesAbsent(NsecProof[] denial, DnsName name)
        => !denial.Any(item => item.Owner.IsSubdomainOf(name) || item.Next.IsSubdomainOf(name))
            && denial.Any(item => item.Covers(name));

    private static DnsName Closest(DnsName origin, DnsName name, NsecProof[] denial)
    {
        var candidate = name.Parent;
        while (!candidate.Equals(origin) && !denial.Any(item => item.Owner.IsSubdomainOf(candidate) || item.Next.IsSubdomainOf(candidate)))
            candidate = candidate.Parent;
        return candidate;
    }

    private static DnsName NextCloser(DnsName name, DnsName closest)
    {
        while (!name.Parent.Equals(closest))
            name = name.Parent;
        return name;
    }
}
