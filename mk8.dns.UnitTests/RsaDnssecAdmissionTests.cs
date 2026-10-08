using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RsaDnssecAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void RsaAnchorRefusesUnsupportedFlagsProtocolAlgorithmOrPublicIntegers(int defect)
    {
        using var fixture = new RsaDnssecFixture();
        var bytes = fixture.Key.GetData();
        if (defect == 0) BinaryPrimitives.WriteUInt16BigEndian(bytes, 1);
        if (defect == 1) BinaryPrimitives.WriteUInt16BigEndian(bytes, 385);
        if (defect == 2) bytes[2] = 2;
        if (defect == 3) bytes[3] = 10;
        if (defect == 4) bytes[5] = 0;
        if (defect == 5) bytes = bytes[..^1];
        var key = new DnsRecord(fixture.Origin, 48, 300, bytes);
        if (defect == 5)
        {
            // A truncated value can still have structurally valid size/oddness. It cannot validate the original signature/pin.
            Assert.False(fixture.Validator().TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.Key), [key], [fixture.Sign([fixture.Key])], out _));
        }
        else Assert.Throws<ArgumentException>(() => new DnssecTrustAnchor(key));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Sha256DsRequiresEntireDigestOwnerKeytagAndAlgorithmMatch(int defect)
    {
        using var fixture = new RsaDnssecFixture();
        var bytes = DnssecKeys.CreateDs(fixture.Key, 0).GetData();
        if (defect == 0) bytes[^1] ^= 1;
        if (defect == 1) bytes[0] ^= 1;
        if (defect == 2) bytes[2] = 13;
        var ds = new DnsRecord(defect == 3 ? DnsName.Parse("other.") : fixture.Origin, 43, 0, bytes);
        Assert.False(fixture.Validator().TryAuthenticateAnchor(new DnssecTrustAnchor(ds), [fixture.Key], [fixture.Sign([fixture.Key])], out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void SignatureAlgorithmTagWidthAndMacMustMatchAdmittedRsaKey(int defect)
    {
        using var fixture = new RsaDnssecFixture(); var record = DnssecFixture.A();
        var signature = fixture.Sign([record]); var data = signature.GetData();
        if (defect == 0) data[2] = 13;
        if (defect == 1) data[16] ^= 1;
        if (defect == 2) data = data[..^1];
        if (defect == 3) data[^1] ^= 1;
        Assert.False(DnssecRrsetVerifier.TryVerify([record], new DnsRecord(record.Owner, 46, 300, data), fixture.Key, 100,
            RsaDnssecFixture.Verifier, out _));
    }

    [Fact]
    public void AlgorithmMismatchCannotReachEvenAnAcceptingProvider()
    {
        using var fixture = new RsaDnssecFixture(512); var record = DnssecFixture.A(); var signature = fixture.Sign([record]);
        var data = signature.GetData(); data[2] = 13; var verifier = new AcceptingVerifier();
        Assert.False(DnssecRrsetVerifier.TryVerify([record], new DnsRecord(record.Owner, 46, 300, data), fixture.Key, 100, verifier, out _));
        Assert.Equal(0, verifier.Calls);
    }

    [Fact]
    public void ExistingSignerAndSignedAdmissionDoNotAcquireRsaAuthority()
    {
        using var rsa = new RsaDnssecFixture(); using var ecdsa = DnssecFixture.Key();
        var record = DnssecFixture.A();
        Assert.Throws<FormatException>(() => DnssecRrsetSigner.Sign([record], rsa.Key, ecdsa, RsaDnssecFixture.Verifier, DnssecFixture.Window));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.ValidateCapacity(AuthorityFixture.Zone(), rsa.Key));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.Verify(new ZoneContents(AuthorityFixture.Zone(), [rsa.Key]), 100, RsaDnssecFixture.Verifier));
    }

    private sealed class AcceptingVerifier : IDnssecSignatureVerifier
    {
        internal int Calls { get; private set; }
        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
        { Calls++; return true; }
    }
}
