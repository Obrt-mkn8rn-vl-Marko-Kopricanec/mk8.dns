using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

internal static class DnssecAnchorProof
{
    internal sealed record Verified(DnssecSignatureWindow Window, uint OriginalTtl, uint ReceivedTtl);
    internal static bool TryKey(DnsRecord record, bool revoked, out byte[] identity)
    {
        identity = record.GetData();
        if (record.Type != 48 || identity.Length < 4
            || (BinaryPrimitives.ReadUInt16BigEndian(identity) & 385) != (revoked ? 385 : 257))
            return false;
        identity[1] &= 127;
        return DnssecValidationInput.IsUsableKey(new DnsRecord(record.Owner, 48, 0, identity));
    }

    internal static string Identity(byte[] data) => Convert.ToHexString(data);

    // A REVOKE key is usable ONLY for its own DNSKEY revocation proof. General
    // key admission and the accepted RRset verifier continue to reject it.
    internal static bool TryVerify(DnsRecord[] records, DnsRecord signature, DnsRecord key, uint now,
        IDnssecSignatureVerifier verifier, ref int attempts, out Verified? proof)
    {
        proof = null;
        try
        {
            var data = RrsigData.Decode(signature);
            var value = key.GetData();
            if (!signature.Owner.Equals(key.Owner) || data.Type != 48 || !data.Signer.Equals(key.Owner)
                || data.Labels != key.Owner.LabelCount || data.Algorithm != value[3]
                || data.KeyTag != KeyTag(value) || !data.Window.Contains(now))
                return false;
            if (data.Algorithm == 8 && (!DnssecRsaPublicKey.TryParse(value.AsSpan(4), out var rsa)
                || data.Signature.Length != rsa.SignatureSize))
                return false;
            if (++attempts > DnssecChainValidator.MaximumVerificationAttempts)
                return false;
            byte[] message = [.. data.Header(), .. DnssecCanonical.GetRrset(records, data.OriginalTtl, data.Labels)];
            var digest = data.Algorithm == 14 ? SHA384.HashData(message) : SHA256.HashData(message);
            if (!verifier.VerifyHash(data.Algorithm, value.AsSpan(4), digest, data.Signature))
                return false;
            proof = new Verified(data.Window, data.OriginalTtl,
                Math.Min(data.OriginalTtl, Math.Min(signature.Ttl, records.Min(record => record.Ttl))));
            return true;
        }
        catch (Exception error) when (error is FormatException or ArgumentException or CryptographicException)
        {
            return false;
        }
    }

    private static ushort KeyTag(byte[] data)
    {
        uint sum = 0;
        for (var index = 0; index < data.Length; index++)
            sum += (index & 1) == 0 ? (uint)data[index] << 8 : data[index];
        sum += sum >> 16;
        return (ushort)sum;
    }
}
