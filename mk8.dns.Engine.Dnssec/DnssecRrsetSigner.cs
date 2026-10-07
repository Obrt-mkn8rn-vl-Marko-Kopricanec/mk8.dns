using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public static class DnssecRrsetSigner
{
    public static DnsRecord Sign(IReadOnlyList<DnsRecord> records, DnsRecord dnskey, IDnssecSigningKey key, IDnssecSignatureVerifier verifier, DnssecSignatureWindow window)
    {
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(window);
        var publicKey = DnssecKeys.ReadKey(dnskey);
        if (key.Algorithm != 13 || !key.GetPublicKey().AsSpan().SequenceEqual(publicKey.AsSpan(4)))
            throw new ArgumentException("The signing key does not match the algorithm-13 DNSKEY.", nameof(key));
        if (records.Count is 0 or > 10_000)
            throw new ArgumentException("Invalid signing RRset bounds.", nameof(records));
        var items = records.ToArray();
        if (items.Any(record => record is null))
            throw new ArgumentException("Null signing records are not permitted.", nameof(records));
        var first = items[0];
        if (!first.Owner.IsSubdomainOf(dnskey.Owner) || first.Type == 46 || items.Any(record => record.Ttl != first.Ttl))
            throw new ArgumentException("Invalid signing owner, type or TTL.", nameof(records));
        var data = new RrsigData
        {
            Type = first.Type,
            Algorithm = 13,
            Labels = (byte)(first.Owner.LabelCount - (DnssecData.IsWildcard(first.Owner) ? 1 : 0)),
            OriginalTtl = first.Ttl,
            Window = window,
            KeyTag = DnssecKeys.KeyTag(dnskey),
            Signer = dnskey.Owner,
            Signature = [],
        };
        var header = data.Header();
        var canonical = DnssecCanonical.GetRrset(items, first.Ttl, data.Labels);
        byte[] signed = [.. header, .. canonical];
        var digest = SHA256.HashData(signed);
        var signature = key.SignHash(digest);
        if (signature.Length != 64 || !verifier.VerifyHash(13, publicKey.AsSpan(4), digest, signature))
            throw new CryptographicException("The provider returned an invalid algorithm-13 signature.");
        return new DnsRecord(first.Owner, 46, first.Ttl, [.. header, .. signature]);
    }
}
