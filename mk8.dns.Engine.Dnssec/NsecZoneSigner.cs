using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public static class NsecZoneSigner
{
    public static SignedZone Sign(AuthoritativeZone zone, IDnssecSigningKey key, IDnssecSignatureVerifier verifier, DnssecSignatureWindow window, uint dnskeyTtl = 3600, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(zone);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(window);
        cancellationToken.ThrowIfCancellationRequested();
        if (key.Algorithm != 13)
            throw new ArgumentException("This signing profile requires algorithm 13.", nameof(key));
        var dnskey = DnssecKeys.CreateDnskey(zone.Origin, dnskeyTtl, key.GetPublicKey());
        var original = zone.GetAllRecords();
        var cuts = original.Where(record => record.Type == 2 && !record.Owner.Equals(zone.Origin)).Select(record => record.Owner).ToHashSet();
        var owners = original.Append(dnskey).GroupBy(record => record.Owner).Select(group => new Owner(group.Key, group.ToArray(), FindCut(group.Key, zone.Origin, cuts)))
            .Where(owner => owner.Cut is null || owner.Cut.Equals(owner.Name)).OrderBy(owner => owner.Name, DnssecNameOrder.Instance).ToArray();
        List<DnsRecord> denial = new(owners.Length);
        List<DnsRecord> authoritative = [];
        var denialTtl = Math.Min(zone.Soa.Ttl, zone.Soa.GetSoaMinimum());
        for (var index = 0; index < owners.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var owner = owners[index];
            var types = owner.Records.Where(record => owner.Cut is null || record.Type is 2 or 43).Select(record => record.Type).Append((ushort)46).Append((ushort)47);
            var bitmap = NsecBitmap.Encode(types);
            var next = owners[(index + 1) % owners.Length].Name.ToWire();
            denial.Add(new DnsRecord(owner.Name, 47, denialTtl, [.. next, .. bitmap]));
            authoritative.AddRange(owner.Records.Where(record => owner.Cut is null || record.Type == 43));
        }
        var rrsets = authoritative.Concat(denial).GroupBy(record => (record.Owner, record.Type)).Select(group => group.ToArray()).ToArray();
        var predictedCount = original.Count + 1 + denial.Count + rrsets.Length;
        var predictedBytes = original.Append(dnskey).Concat(denial).Sum(record => (long)record.GetOwnerWire().Length + 10 + record.GetData().Length)
            + rrsets.Sum(records => (long)records[0].GetOwnerWire().Length + 10 + 18 + zone.Origin.ToWire().Length + 64);
        if (predictedCount > SignedZone.MaximumRecords || predictedBytes > SignedZone.MaximumWireBytes)
            throw new ArgumentException("Signed zone exceeds its generation bounds.", nameof(zone));
        List<DnsRecord> signed = [.. original, dnskey, .. denial];
        foreach (var rrset in rrsets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            signed.Add(DnssecRrsetSigner.Sign(rrset, dnskey, key, verifier, window));
        }
        return new SignedZone(zone, signed.ToArray(), dnskey, window);
    }

    private static DnsName? FindCut(DnsName name, DnsName origin, HashSet<DnsName> cuts)
    {
        DnsName? cut = null;
        for (var ancestor = name; !ancestor.Equals(origin); ancestor = ancestor.Parent)
            if (cuts.Contains(ancestor))
                cut = ancestor;
        return cut;
    }

    private sealed record Owner(DnsName Name, DnsRecord[] Records, DnsName? Cut);
}
