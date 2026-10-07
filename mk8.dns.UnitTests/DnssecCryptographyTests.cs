using System.Security.Cryptography;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecCryptographyTests
{
    [Fact]
    public void GeneratedKeySignsSha256AndReturnsIndependentPublicCopies()
    {
        using var key = EcdsaP256DnssecSigningKey.Create();
        var publicKey = key.GetPublicKey();
        var digest = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = key.SignHash(digest);
        Assert.Equal((byte)13, key.Algorithm);
        Assert.Equal(64, publicKey.Length);
        Assert.Equal(64, signature.Length);
        var verifier = new EcdsaP256DnssecVerifier();
        Assert.True(verifier.VerifyHash(13, publicKey, digest, signature));
        publicKey[0] ^= 1;
        Assert.NotEqual(publicKey, key.GetPublicKey());
        digest[0] ^= 1;
        Assert.False(verifier.VerifyHash(13, key.GetPublicKey(), digest, signature));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void SigningRequiresExactlySha256Width(int length)
    {
        using var key = DnssecFixture.Key();
        Assert.Throws<ArgumentException>(() => key.SignHash(new byte[length]));
    }

    [Theory]
    [InlineData(14, 64, 32, 64)]
    [InlineData(13, 63, 32, 64)]
    [InlineData(13, 65, 32, 64)]
    [InlineData(13, 64, 31, 64)]
    [InlineData(13, 64, 33, 64)]
    [InlineData(13, 64, 32, 63)]
    [InlineData(13, 64, 32, 65)]
    [InlineData(13, 64, 32, 64)]
    public void UnsupportedWidthsAlgorithmsAndInvalidPointsAreRejected(byte algorithm, int point, int digest, int signature) => Assert.False(new EcdsaP256DnssecVerifier().VerifyHash(algorithm, new byte[point], new byte[digest], new byte[signature]));

    [Fact]
    public void ImportRejectsWrongCurveTrailingMalformedAndExcessInput()
    {
        using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var wrongBytes = wrong.ExportPkcs8PrivateKey();
        try { Assert.Throws<CryptographicException>(() => EcdsaP256DnssecSigningKey.ImportPkcs8(wrongBytes)); }
        finally { CryptographicOperations.ZeroMemory(wrongBytes); }
        var fixture = Convert.FromBase64String(DnssecFixture.Pkcs8);
        Assert.Throws<CryptographicException>(() => EcdsaP256DnssecSigningKey.ImportPkcs8([.. fixture, 0]));
        Assert.Throws<CryptographicException>(() => EcdsaP256DnssecSigningKey.ImportPkcs8([1, 2, 3]));
        Assert.Throws<ArgumentException>(() => EcdsaP256DnssecSigningKey.ImportPkcs8([]));
        Assert.Throws<ArgumentException>(() => EcdsaP256DnssecSigningKey.ImportPkcs8(new byte[4097]));
        using var imported = EcdsaP256DnssecSigningKey.ImportPkcs8(fixture);
        Array.Fill(fixture, (byte)0);
        Assert.True(new EcdsaP256DnssecVerifier().VerifyHash(13, imported.GetPublicKey(), new byte[32], imported.SignHash(new byte[32])));
    }

    [Fact]
    public void DisposalIsTerminalAndIdempotent()
    {
        using var key = DnssecFixture.Key();
        key.Dispose();
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(key.GetPublicKey);
        Assert.Throws<ObjectDisposedException>(() => key.SignHash(new byte[32]));
    }

    [Fact]
    public async Task ConcurrentDisposalAllowsOnlyValidCompletedSignaturesOrTerminalRefusal()
    {
        using var key = DnssecFixture.Key();
        var point = key.GetPublicKey();
        var digest = new byte[32];
        Assert.True(new EcdsaP256DnssecVerifier().VerifyHash(13, point, digest, key.SignHash(digest)));
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var work = Enumerable.Range(0, 16).Select(_ => Task.Run(async () =>
        {
            await start.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
            try { return key.SignHash(digest); }
            catch (ObjectDisposedException) { return null; }
        })).ToArray();
        var closing = Task.Run(async () => { await start.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true); key.Dispose(); });
        start.SetResult();
        var replies = await Task.WhenAll(work).ConfigureAwait(true);
        await closing.ConfigureAwait(true);
        foreach (var reply in replies.Where(reply => reply is not null))
            Assert.True(new EcdsaP256DnssecVerifier().VerifyHash(13, point, digest, reply));
        Assert.Throws<ObjectDisposedException>(key.GetPublicKey);
    }
}
