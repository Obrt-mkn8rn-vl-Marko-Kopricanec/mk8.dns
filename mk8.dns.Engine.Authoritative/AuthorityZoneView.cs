using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Authoritative;

internal sealed class AuthorityZoneView
{
    internal AuthorityZoneView(ZoneContents contents, IDnssecSignatureVerifier? verifier)
    {
        Source = contents.Source;
        if (contents.IsSigned)
            Security = SignedZoneAdmission.VerifyRetained(contents, verifier ?? throw new FormatException("Signed authority requires a verifier."));
    }

    internal AuthoritativeZone Source { get; }
    internal DnsName Origin => Source.Origin;
    internal VerifiedSignedZone? Security { get; }
    internal IReadOnlyList<DnsRecord> GetRecords(DnsName name) => Security?.GetRecords(name) ?? Source.GetRecords(name);

    internal void AddRrset(List<DnsRecord> destination, IReadOnlyList<DnsRecord> records, DnsName owner, uint now, bool dnssecOk)
    {
        if (records.Count == 0)
            return;
        var sourceOwner = records[0].Owner;
        foreach (var record in records)
            destination.Add(record.WithOwner(owner).WithTtl(Security?.BoundTtl(record.Ttl, now) ?? record.Ttl));
        if (dnssecOk && Security?.GetSignature(sourceOwner, records[0].Type) is { } signature)
        {
            var ttl = Math.Min(signature.Ttl, records.Min(record => record.Ttl));
            destination.Add(signature.WithOwner(owner).WithTtl(Security.BoundTtl(ttl, now)));
        }
    }

    internal void AddProof(List<DnsRecord> destination, DnsName name, uint now, bool dnssecOk)
    {
        if (!dnssecOk || Security is null)
            return;
        var proof = Security.GetCover(name);
        if (!destination.Any(record => record.Type == 47 && record.Owner.Equals(proof.Owner)))
            AddRrset(destination, [proof], proof.Owner, now, dnssecOk: true);
    }
}
