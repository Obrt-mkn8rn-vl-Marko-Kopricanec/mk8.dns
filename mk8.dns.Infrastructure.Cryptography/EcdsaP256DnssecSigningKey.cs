using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure.Cryptography;

public sealed class EcdsaP256DnssecSigningKey : IDnssecSigningKey, IDisposable
{
    private readonly Lock gate = new();
    private readonly ECDsa key;
    private readonly byte[] publicKey;
    private bool disposed;

    private EcdsaP256DnssecSigningKey(ECDsa key)
    {
        var parameters = key.ExportParameters(false);
        if (!string.Equals(parameters.Curve.Oid.Value, "1.2.840.10045.3.1.7", StringComparison.Ordinal)
            || parameters.Q.X?.Length != 32 || parameters.Q.Y?.Length != 32)
            throw new CryptographicException("DNSSEC algorithm 13 requires named NIST P-256.");
        this.key = key;
        publicKey = [.. parameters.Q.X, .. parameters.Q.Y];
    }

    public byte Algorithm => 13;

    public static EcdsaP256DnssecSigningKey Create()
    {
        var provider = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try { return new EcdsaP256DnssecSigningKey(provider); }
        catch { provider.Dispose(); throw; }
    }

    public static EcdsaP256DnssecSigningKey ImportPkcs8(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length is 0 or > 4096)
            throw new ArgumentException("Invalid private-key input bounds.", nameof(privateKey));
        var provider = ECDsa.Create();
        try
        {
            provider.ImportPkcs8PrivateKey(privateKey, out var consumed);
            if (consumed != privateKey.Length)
                throw new CryptographicException("Private-key input has trailing data.");
            return new EcdsaP256DnssecSigningKey(provider);
        }
        catch { provider.Dispose(); throw; }
    }

    public byte[] GetPublicKey()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return (byte[])publicKey.Clone();
        }
    }

    public byte[] SignHash(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != 32)
            throw new ArgumentException("Algorithm 13 requires a SHA-256 digest.", nameof(digest));
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
                return;
            disposed = true;
            key.Dispose();
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }
}
