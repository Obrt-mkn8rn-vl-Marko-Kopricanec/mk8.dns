using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

internal sealed class Nsec3ProofSet(Nsec3Proof[] proofs)
{
    private readonly Dictionary<DnsName, byte[]> hashes = [];
    internal Nsec3Proof[] Proofs { get; } = proofs;

    internal byte[] Hash(DnsName name)
    {
        if (hashes.TryGetValue(name, out var result)) return result;
        DnssecData.Require(hashes.Count < DnssecChainValidator.MaximumNsec3Hashes);
        // SHA-1 is the mandated NSEC3 name hash, never a signature or DS digest.
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        hash.AppendData(name.ToWire());
        hash.AppendData(Proofs[0].Salt);
        result = hash.GetHashAndReset();
        hashes.Add(name, result);
        return result;
    }

    internal Nsec3Proof? Match(DnsName name)
    {
        var hash = Hash(name);
        return Proofs.SingleOrDefault(item => item.Matches(hash));
    }

    internal Nsec3Proof? Cover(DnsName name)
    {
        var hash = Hash(name);
        return Proofs.FirstOrDefault(item => item.Covers(hash));
    }

    internal bool Blocks(DnsQuestion question, DnsName origin)
    {
        for (var name = question.Name; ; name = name.Parent)
        {
            var match = Match(name);
            if (match is not null && (match.Delegation && (!question.Name.Equals(name) || question.Type != 43)
                || match.Types.Contains((ushort)39) && !question.Name.Equals(name))) return true;
            if (name.Equals(origin)) return false;
        }
    }

    internal DnsName? Closest(DnsName name, DnsName origin)
    {
        for (var candidate = name.Parent; ; candidate = candidate.Parent)
        {
            var match = Match(candidate);
            if (match is not null) return match.Delegation || match.Types.Contains((ushort)39) ? null : candidate;
            if (candidate.Equals(origin)) return null;
        }
    }
}
