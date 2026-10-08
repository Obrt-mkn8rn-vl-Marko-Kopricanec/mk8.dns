using System.Security.Cryptography;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RsaDnssecProviderTests
{
    [Theory]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(4096)]
    public void NativeProviderVerifiesOnlyExactModulusWidthPkcs1Sha256Signature(int bits)
    {
        using var key = RSA.Create(bits); var data = SHA256.HashData("bounded-public-RSA-fixture"u8);
        var publicKey = key.ExportParameters(false);
        byte[] wire = [checked((byte)publicKey.Exponent!.Length), .. publicKey.Exponent, .. publicKey.Modulus!];
        var signature = key.SignHash(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var verifier = new RsaSha256DnssecVerifier();
        Assert.True(verifier.VerifyHash(8, wire, data, signature));
        Assert.False(verifier.VerifyHash(13, wire, data, signature));
        Assert.False(verifier.VerifyHash(8, wire, data.AsSpan(0, 31), signature));
        Assert.False(verifier.VerifyHash(8, wire, data, signature.AsSpan(0, signature.Length - 1)));
        Assert.False(verifier.VerifyHash(8, wire, data, [0, .. signature]));
        signature[^1] ^= 1; Assert.False(verifier.VerifyHash(8, wire, data, signature));
    }

    [Fact]
    public void PssAndWrongHashNeverBecomeAlgorithm8Pkcs1Authentication()
    {
        using var key = RSA.Create(1024); var digest = SHA256.HashData("test"u8); var parts = key.ExportParameters(false);
        byte[] wire = [checked((byte)parts.Exponent!.Length), .. parts.Exponent, .. parts.Modulus!];
        var verifier = new DnssecSignatureVerifier();
        Assert.False(verifier.VerifyHash(8, wire, digest, key.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)));
        Assert.False(verifier.VerifyHash(8, wire, digest, key.SignHash(SHA384.HashData("test"u8), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1)));
        Assert.False(verifier.VerifyHash(10, wire, digest, new byte[128]));
        Assert.False(verifier.VerifyHash(8, [], digest, new byte[128]));
    }
}
