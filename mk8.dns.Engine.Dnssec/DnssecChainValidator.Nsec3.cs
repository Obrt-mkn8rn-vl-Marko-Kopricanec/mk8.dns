using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed partial class DnssecChainValidator
{
    public const int MaximumNsec3Records = 8;
    public const int MaximumNsec3Hashes = 256;

    // Supplied-proof APIs: the caller selects actual containing/parent cuts.
    // A true Opt-Out DS result is a delegation marker, never authenticated data.
    public bool TryAuthenticateNsec3NameError(AuthenticatedDnskeySet keys, DnsQuestion question, IReadOnlyList<DnsRecord> soa,
        IReadOnlyList<DnsRecord> nsec3s, IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl)
        => TryNsec3Negative(keys, question, soa, nsec3s, signatures, nameError: true, out authenticatedTtl);

    public bool TryAuthenticateNsec3NoData(AuthenticatedDnskeySet keys, DnsQuestion question, IReadOnlyList<DnsRecord> soa,
        IReadOnlyList<DnsRecord> nsec3s, IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl)
        => TryNsec3Negative(keys, question, soa, nsec3s, signatures, nameError: false, out authenticatedTtl);

    public bool TryAuthenticateNsec3DsAbsence(AuthenticatedDnskeySet parent, DnsName child, IReadOnlyList<DnsRecord> nsec3s,
        IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl, out bool optOut)
    {
        ArgumentNullException.ThrowIfNull(parent);
        ArgumentNullException.ThrowIfNull(child);
        ArgumentNullException.ThrowIfNull(nsec3s);
        ArgumentNullException.ThrowIfNull(signatures);
        authenticatedTtl = 0;
        optOut = false;
        var question = new DnsQuestion(child, 43, 1);
        var stamp = ReadClock();
        if (!AdmitQuestion(parent, question, stamp) || child.Equals(parent.Origin)
            || !TryNsec3Inputs(parent.Origin, nsec3s, signatures, out var denial, out var sigs)
            || !AuthenticateNsec3s(parent, denial, sigs, stamp, new Budget(), out var proofs) || denial.Blocks(question, parent.Origin)) return false;
        var exact = denial.Match(child);
        var isOptOut = false;
        if (exact is not null)
        {
            if (!exact.Delegation || !exact.Lacks(43) || exact.Types.Contains((ushort)39)) return false;
        }
        else
        {
            var closest = denial.Closest(child, parent.Origin);
            if (closest is null || denial.Cover(NextCloser(child, closest)) is not { OptOut: true }) return false;
            isOptOut = true;
        }
        if (!FinishResponse(parent, stamp, proofs, uint.MaxValue, out authenticatedTtl)) return false;
        optOut = isOptOut;
        return true;
    }

    private bool TryNsec3Negative(AuthenticatedDnskeySet keys, DnsQuestion question, IReadOnlyList<DnsRecord> soa,
        IReadOnlyList<DnsRecord> nsec3s, IReadOnlyList<DnsRecord> signatures, bool nameError, out uint ttl)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(soa);
        ArgumentNullException.ThrowIfNull(nsec3s);
        ArgumentNullException.ThrowIfNull(signatures);
        ttl = 0;
        var stamp = ReadClock();
        if (!AdmitQuestion(keys, question, stamp) || question.Type == 43 && question.Name.Equals(keys.Origin)
            || !nameError && question.Name.Equals(keys.Origin) && question.Type is 6 or 48
            || !DnssecValidationInput.TryRrset(soa, keys.Origin, 6, 1, out var soaRecords)
            || !TryNsec3Inputs(keys.Origin, nsec3s, signatures, out var denial, out var sigs)) return false;
        var budget = new Budget();
        if (!TryVerifyResponse(soaRecords, sigs, keys, stamp, budget, (byte)keys.Origin.LabelCount, out var soaProof)
            || !AuthenticateNsec3s(keys, denial, sigs, stamp, budget, out var proofs) || denial.Blocks(question, keys.Origin)) return false;
        proofs.Add(soaProof);
        var exact = denial.Match(question.Name);
        if (!nameError && exact is not null)
        {
            if (!exact.Lacks(question.Type)) return false;
        }
        else
        {
            // A matched original name cannot be NXDOMAIN. DS requires an exact
            // parent match here; Opt-Out is confined to the separate marker API.
            if (exact is not null || question.Type == 43) return false;
            var closest = denial.Closest(question.Name, keys.Origin);
            if (closest is null || denial.Cover(NextCloser(question.Name, closest)) is not { OptOut: false }) return false;
            var wildcard = closest.PrependLabel([(byte)'*']);
            if (nameError ? denial.Cover(wildcard) is not { OptOut: false } : denial.Match(wildcard) is not { } source
                || source.Delegation || !source.Lacks(question.Type)) return false;
        }
        return FinishResponse(keys, stamp, proofs, soaRecords[0].GetSoaMinimum(), out ttl);
    }

    private static bool TryNsec3Inputs(DnsName origin, IReadOnlyList<DnsRecord> input, IReadOnlyList<DnsRecord> signatures,
        out Nsec3ProofSet denial, out DnsRecord[] sigs)
    {
        denial = new Nsec3ProofSet([]);
        sigs = [];
        if (input.Count is 0 or > MaximumNsec3Records || !DnssecValidationInput.TrySignatures(signatures, out sigs)) return false;
        var snapshot = input.ToArray();
        if (snapshot.Length != input.Count || snapshot.Any(record => record is null || record.Type != 50)
            || snapshot.Select(record => record.Owner).Distinct().Count() != snapshot.Length) return false;
        try
        {
            var items = snapshot.Select(record => Nsec3Proof.Decode(record, origin)).ToArray();
            if (items.Any(item => !item.Salt.AsSpan().SequenceEqual(items[0].Salt)
                || items.Any(other => item.Covers(other.Owner) || item.Covers(other.Next)))) return false;
            var candidate = new Nsec3ProofSet(items);
            var apex = candidate.Hash(origin);
            if (items.Any(item => item.Types.Contains((ushort)6) && !item.Matches(apex))) return false;
            denial = candidate;
            return true;
        }
        catch (FormatException) { return false; }
    }

    private bool AuthenticateNsec3s(AuthenticatedDnskeySet keys, Nsec3ProofSet denial, DnsRecord[] sigs, Stamp stamp,
        Budget budget, out List<Proof> proofs)
    {
        proofs = new List<Proof>(denial.Proofs.Length + 1);
        foreach (var item in denial.Proofs)
        {
            if (!TryVerifyResponse([item.Record], sigs, keys, stamp, budget, (byte)item.Record.Owner.LabelCount, out var proof)) return false;
            proofs.Add(proof);
        }
        return true;
    }
}
