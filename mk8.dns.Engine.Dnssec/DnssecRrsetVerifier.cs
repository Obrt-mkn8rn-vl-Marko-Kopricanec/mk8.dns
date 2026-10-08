using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public static class DnssecRrsetVerifier
{
    public static bool TryVerify(IReadOnlyList<DnsRecord> records, DnsRecord signature, DnsRecord dnskey, uint now, IDnssecSignatureVerifier verifier, out uint authenticatedTtl)
    {
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(dnskey);
        ArgumentNullException.ThrowIfNull(verifier);
        authenticatedTtl = 0;
        if (records.Count is 0 or > 10_000)
            return false;
        try
        {
            var items = records.ToArray();
            if (items.Any(record => record is null))
                return false;
            var key = DnssecKeys.ReadValidationKey(dnskey);
            var data = RrsigData.Decode(signature);
            if (data.Algorithm != key[3] || data.Algorithm == 8
                && (!DnssecRsaPublicKey.TryParse(key.AsSpan(4), out var rsa) || data.Signature.Length != rsa.SignatureSize))
                return false;
            var first = items[0];
            var minimumLabels = data.Signer.LabelCount - (first.Owner.Equals(data.Signer) && DnssecData.IsWildcard(data.Signer) ? 1 : 0);
            if (!signature.Owner.Equals(first.Owner) || data.Type != first.Type || data.Type == 46
                || !data.Signer.Equals(dnskey.Owner) || !first.Owner.IsSubdomainOf(data.Signer)
                || data.Labels < minimumLabels || data.Labels > first.Owner.LabelCount
                || DnssecData.IsWildcard(first.Owner) && data.Labels != first.Owner.LabelCount - 1
                || data.KeyTag != DnssecKeys.KeyTag(dnskey) || !data.Window.Contains(now))
                return false;
            var canonical = DnssecCanonical.GetRrset(items, data.OriginalTtl, data.Labels);
            byte[] signed = [.. data.Header(), .. canonical];
            var digest = data.Algorithm == 14 ? SHA384.HashData(signed) : SHA256.HashData(signed);
            if (!verifier.VerifyHash(data.Algorithm, key.AsSpan(4), digest, data.Signature))
                return false;
            authenticatedTtl = Math.Min(Math.Min(items.Min(record => record.Ttl), signature.Ttl),
                Math.Min(data.OriginalTtl, unchecked(data.Window.Expiration - now)));
            return true;
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException)
        {
            return false;
        }
    }
}
