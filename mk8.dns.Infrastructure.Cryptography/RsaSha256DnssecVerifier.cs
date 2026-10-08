using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure.Cryptography;

public sealed class RsaSha256DnssecVerifier : IDnssecSignatureVerifier
{
    public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        if (algorithm != 8 || digest.Length != 32 || !DnssecRsaPublicKey.TryParse(publicKey, out var material)
            || signature.Length != material.SignatureSize)
            return false;
        try
        {
            using var key = RSA.Create(new RSAParameters { Exponent = material.GetExponent(), Modulus = material.GetModulus() });
            return key.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException) { return false; }
    }
}
