using System.Security.Cryptography;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class P384DnssecProviderTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NativeAndCompositeVerifiersUseP384FixedFieldSignature(bool composite)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384); var material = key.ExportParameters(false);
        byte[] point = [.. material.Q.X!, .. material.Q.Y!]; var digest = SHA384.HashData("nonproduction DNSSEC fixture"u8);
        var signature = key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var provider = composite ? (Mk8.Dns.Domain.IDnssecSignatureVerifier)new DnssecSignatureVerifier() : new EcdsaP384DnssecVerifier();
        Assert.Equal(96, signature.Length); Assert.True(provider.VerifyHash(14, point, digest, signature));
        signature[^1] ^= 1; Assert.False(provider.VerifyHash(14, point, digest, signature));
    }

    [Theory]
    [InlineData(8, 96, 48, 96)]
    [InlineData(13, 96, 48, 96)]
    [InlineData(14, 95, 48, 96)]
    [InlineData(14, 97, 48, 96)]
    [InlineData(14, 96, 32, 96)]
    [InlineData(14, 96, 64, 96)]
    [InlineData(14, 96, 48, 95)]
    [InlineData(14, 96, 48, 97)]
    public void AlgorithmPointDigestAndSignatureWidthsAreExact(byte algorithm, int point, int digest, int signature)
        => Assert.False(new EcdsaP384DnssecVerifier().VerifyHash(algorithm, new byte[point], new byte[digest], new byte[signature]));

    [Fact]
    public void InvalidPointAndDerSignatureCannotBeAccepted()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384); var material = key.ExportParameters(false);
        var digest = SHA384.HashData("nonproduction"u8); byte[] point = [.. material.Q.X!, .. material.Q.Y!];
        var der = key.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);
        Assert.False(new EcdsaP384DnssecVerifier().VerifyHash(14, point, digest, der));
        Assert.False(new EcdsaP384DnssecVerifier().VerifyHash(14, new byte[96], digest, new byte[96]));
    }
}
