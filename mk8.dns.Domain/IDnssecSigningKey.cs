namespace Mk8.Dns.Domain;

public interface IDnssecSigningKey
{
    byte Algorithm { get; }
    byte[] GetPublicKey();
    byte[] SignHash(ReadOnlySpan<byte> digest);
}
