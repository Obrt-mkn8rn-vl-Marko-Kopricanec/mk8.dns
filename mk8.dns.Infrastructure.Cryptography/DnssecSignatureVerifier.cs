using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure.Cryptography;

public sealed class DnssecSignatureVerifier : IDnssecSignatureVerifier
{
    private readonly EcdsaP256DnssecVerifier ecdsa = new();
    private readonly RsaSha256DnssecVerifier rsa = new();

    public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        => algorithm switch
        {
            8 => rsa.VerifyHash(algorithm, publicKey, digest, signature),
            13 => ecdsa.VerifyHash(algorithm, publicKey, digest, signature),
            _ => false,
        };
}
