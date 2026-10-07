namespace Mk8.Dns.Domain;

public interface IDnssecSignatureVerifier
{
    bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature);
}
