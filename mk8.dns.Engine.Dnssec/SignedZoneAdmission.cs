using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public static class SignedZoneAdmission
{
    public static void ValidateCapacity(AuthoritativeZone source, DnsRecord dnskey)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(dnskey);
        DnssecServingProfile.ValidateSource(source);
        DnssecData.Require(dnskey.Owner.Equals(source.Origin));
        _ = DnssecKeys.ReadKey(dnskey);
        var owners = GetOwners(source, dnskey);
        var sets = owners.SelectMany(owner => owner.Authoritative).GroupBy(record => (record.Owner, record.Type)).ToArray();
        var signatures = sets.Select(set => set.Key.Owner).Concat(owners.Select(owner => owner.Name)).ToArray();
        var bytes = source.GetAllRecords().Append(dnskey).Sum(record => (long)record.GetOwnerWire().Length + 8 + record.GetData().Length)
            + signatures.Sum(owner => (long)owner.ToWire().Length + 90 + source.Origin.ToWire().Length);
        for (var index = 0; index < owners.Length; index++)
            bytes += owners[index].Name.ToWire().Length + 8 + owners[(index + 1) % owners.Length].Name.ToWire().Length + NsecBitmap.Encode(owners[index].Types).Length;
        DnssecData.Require(source.GetAllRecords().Count + 1 + owners.Length + signatures.Length <= ZoneContents.MaximumRecords
            && bytes <= ZoneSnapshot.MaximumPayloadBytes - 6);
        foreach (var set in sets)
            DnssecData.Require(set.Sum(record => (long)record.GetOwnerWire().Length + 10 + record.GetData().Length)
                + set.Key.Owner.ToWire().Length + 92 + source.Origin.ToWire().Length <= 65_065);
        DnssecData.Require(signatures.GroupBy(owner => owner).All(group => group.Count() * ((long)group.Key.ToWire().Length + 92 + source.Origin.ToWire().Length) <= 65_065));
    }

    public static VerifiedSignedZone Verify(ZoneContents contents, uint now, IDnssecSignatureVerifier verifier)
        => VerifyCore(contents, now, verifier);

    public static VerifiedSignedZone VerifyRetained(ZoneContents contents, IDnssecSignatureVerifier verifier)
        => VerifyCore(contents, null, verifier);

    private static VerifiedSignedZone VerifyCore(ZoneContents contents, uint? now, IDnssecSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(contents);
        ArgumentNullException.ThrowIfNull(verifier);
        try
        {
            return VerifyGeneration(contents, now, verifier);
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("Invalid DNSSEC generation metadata.", exception);
        }
    }

    private static VerifiedSignedZone VerifyGeneration(ZoneContents contents, uint? now, IDnssecSignatureVerifier verifier)
    {
        DnssecServingProfile.ValidateSource(contents.Source);
        var security = contents.GetSecurityRecords();
        var keys = security.Where(record => record.Type == 48).ToArray();
        DnssecData.Require(keys.Length == 1 && keys[0].Owner.Equals(contents.Source.Origin));
        var key = keys[0];
        var keyData = DnssecKeys.ReadKey(key);
        DnssecData.Require(keyData[0] == 1 && keyData[1] == 1);
        var owners = GetOwners(contents.Source, key);
        VerifyDenial(contents.Source, security, owners);
        var sets = owners.SelectMany(owner => owner.Authoritative).Concat(security.Where(record => record.Type == 47))
            .GroupBy(record => (record.Owner, record.Type)).ToDictionary(group => group.Key, group => group.ToArray());
        var signatures = security.Where(record => record.Type == 46).ToArray();
        DnssecData.Require(signatures.Length == sets.Count);
        Dictionary<(DnsName Owner, ushort Type), DnsRecord> admitted = [];
        DnssecSignatureWindow? window = null;
        foreach (var signature in signatures)
        {
            var data = RrsigData.Decode(signature);
            DnssecData.Require(admitted.TryAdd((signature.Owner, data.Type), signature)
                && sets.ContainsKey((signature.Owner, data.Type)));
            var records = sets[(signature.Owner, data.Type)];
            DnssecData.Require(records.Sum(record => (long)record.GetOwnerWire().Length + 10 + record.GetData().Length)
                + signature.GetOwnerWire().Length + 10 + signature.GetData().Length <= 65_065);
            DnssecData.Require(data.Labels == signature.Owner.LabelCount - (DnssecData.IsWildcard(signature.Owner) ? 1 : 0)
                && records.All(record => record.Ttl == data.OriginalTtl) && signature.Ttl == data.OriginalTtl
                && DnssecRrsetVerifier.TryVerify(records, signature, key, now ?? data.Window.Inception, verifier, out _));
            window ??= data.Window;
            DnssecData.Require(window.Inception == data.Window.Inception && window.Expiration == data.Window.Expiration);
        }
        DnssecData.Require(window is not null);
        DnssecData.Require(signatures.GroupBy(record => record.Owner).All(group => group.Sum(record => (long)record.GetOwnerWire().Length + 10 + record.GetData().Length) <= 65_065));
        return new VerifiedSignedZone(contents, key, window!, admitted);
    }

    private static Owner[] GetOwners(AuthoritativeZone source, DnsRecord key)
    {
        var all = source.GetAllRecords();
        var cuts = all.Where(record => record.Type == 2 && !record.Owner.Equals(source.Origin)).Select(record => record.Owner).ToHashSet();
        List<Owner> owners = [];
        foreach (var group in all.Append(key).GroupBy(record => record.Owner))
        {
            DnsName? cut = null;
            for (var ancestor = group.Key; !ancestor.Equals(source.Origin); ancestor = ancestor.Parent)
                if (cuts.Contains(ancestor))
                    cut = ancestor;
            if (cut is not null && !cut.Equals(group.Key))
                continue;
            owners.Add(new Owner(group.Key, group.Where(record => cut is null || record.Type == 43).ToArray(),
                group.Where(record => cut is null || record.Type is 2 or 43).Select(record => record.Type).Append((ushort)46).Append((ushort)47).ToArray()));
        }
        return owners.OrderBy(owner => owner.Name, DnssecNameOrder.Instance).ToArray();
    }

    private static void VerifyDenial(AuthoritativeZone source, IReadOnlyList<DnsRecord> security, Owner[] owners)
    {
        var denial = security.Where(record => record.Type == 47).OrderBy(record => record.Owner, DnssecNameOrder.Instance).ToArray();
        DnssecData.Require(denial.Length == owners.Length);
        var ttl = Math.Min(source.Soa.Ttl, source.Soa.GetSoaMinimum());
        for (var index = 0; index < owners.Length; index++)
        {
            var record = denial[index];
            var next = owners[(index + 1) % owners.Length].Name.ToWire();
            var bitmap = NsecBitmap.Encode(owners[index].Types);
            byte[] expected = [.. next, .. bitmap];
            DnssecData.Require(record.Owner.Equals(owners[index].Name) && record.Ttl == ttl && record.GetData().AsSpan().SequenceEqual(expected));
        }
    }

    private sealed record Owner(DnsName Name, DnsRecord[] Authoritative, ushort[] Types);
}
