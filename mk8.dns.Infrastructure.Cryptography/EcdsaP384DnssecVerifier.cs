using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure.Cryptography;

public sealed class EcdsaP384DnssecVerifier : IDnssecSignatureVerifier
{
    public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        if (algorithm != 14 || publicKey.Length != 96 || digest.Length != 48 || signature.Length != 96)
            return false;
        try
        {
            using var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP384,
                Q = new ECPoint { X = publicKey[..48].ToArray(), Y = publicKey[48..].ToArray() },
            });
            return key.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException) { return false; }
    }
}
