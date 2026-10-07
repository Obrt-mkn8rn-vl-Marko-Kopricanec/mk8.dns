using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure.Cryptography;

public sealed class EcdsaP256DnssecVerifier : IDnssecSignatureVerifier
{
    public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        if (algorithm != 13 || publicKey.Length != 64 || digest.Length != 32 || signature.Length != 64)
            return false;
        try
        {
            using var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = publicKey[..32].ToArray(), Y = publicKey[32..].ToArray() },
            });
            return key.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
