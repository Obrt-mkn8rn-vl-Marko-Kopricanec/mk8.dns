using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class P384DnssecAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void P384DnskeyAdmissionRefusesFlagsProtocolAlgorithmAndNonexactSize(int defect)
    {
        using var fixture = new P384DnssecFixture(); var data = fixture.Key.GetData();
        if (defect == 0) BinaryPrimitives.WriteUInt16BigEndian(data, 1);
        if (defect == 1) BinaryPrimitives.WriteUInt16BigEndian(data, 385);
        if (defect == 2) data[2] = 2;
        if (defect == 3) data[3] = 15;
        if (defect == 4) data = data[..^1];
        if (defect == 5) data = [.. data, 0];
        Assert.Throws<ArgumentException>(() => new DnssecTrustAnchor(new DnsRecord(fixture.Origin, 48, 300, data)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void Sha384AnchorRequiresEntireDigestOwnerTagAlgorithmAndDigestType(int defect)
    {
        using var fixture = new P384DnssecFixture(); var bytes = DnssecKeys.CreateDs(fixture.Key, 0, 4).GetData();
        if (defect == 0) bytes[^1] ^= 1;
        if (defect == 1) bytes[0] ^= 1;
        if (defect == 2) bytes[2] = 13;
        if (defect == 3) bytes[3] = 99;
        var ds = new DnsRecord(defect == 4 ? DnsName.Parse("other.") : fixture.Origin, 43, 0, bytes);
        if (defect == 3) Assert.Throws<ArgumentException>(() => new DnssecTrustAnchor(ds));
        else Assert.False(fixture.Validator().TryAuthenticateAnchor(new DnssecTrustAnchor(ds), [fixture.Key], [fixture.Sign([fixture.Key])], out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void SignatureAlgorithmTagWidthMacAndPointMustBindTheAdmittedKey(int defect)
    {
        using var fixture = new P384DnssecFixture(); var record = DnssecFixture.A(); var signature = fixture.Sign([record]); var data = signature.GetData();
        if (defect == 0) data[2] = 13;
        if (defect == 1) data[16] ^= 1;
        if (defect == 2) data = data[..^1];
        if (defect == 3) data[^1] ^= 1;
        var key = defect == 4 ? new DnsRecord(fixture.Origin, 48, 300, [1, 1, 3, 14, .. new byte[96]]) : fixture.Key;
        Assert.False(DnssecRrsetVerifier.TryVerify([record], new DnsRecord(record.Owner, 46, 300, data), key, 100, P384DnssecFixture.Verifier, out _));
    }

    [Fact]
    public void MismatchedAlgorithmAndWidthsCannotReachPermissiveProvider()
    {
        using var fixture = new P384DnssecFixture(); var record = DnssecFixture.A(); var signature = fixture.Sign([record]); var provider = new AcceptingVerifier();
        foreach (var invalid in new[] { signature.GetData()[..^1], signature.GetData().AsSpan(0, signature.GetData().Length - 32).ToArray() })
            Assert.False(DnssecRrsetVerifier.TryVerify([record], new DnsRecord(record.Owner, 46, 300, invalid), fixture.Key, 100, provider, out _));
        var data = signature.GetData(); data[2] = 13; data = data[..^32];
        Assert.False(DnssecRrsetVerifier.TryVerify([record], new DnsRecord(record.Owner, 46, 300, data), fixture.Key, 100, provider, out _));
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public void ExistingSignerAndSignedServingAdmissionRemainAlgorithm13Only()
    {
        using var fixture = new P384DnssecFixture(); using var signer = DnssecFixture.Key(); var record = DnssecFixture.A();
        Assert.Throws<FormatException>(() => DnssecRrsetSigner.Sign([record], fixture.Key, signer, P384DnssecFixture.Verifier, DnssecFixture.Window));
        Assert.Throws<FormatException>(() => SignedZoneAdmission.ValidateCapacity(AuthorityFixture.Zone(), fixture.Key));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(255)]
    public void UnsupportedDsDigestsAreNotGenerated(byte digest)
    {
        using var fixture = new P384DnssecFixture(); Assert.Throws<ArgumentOutOfRangeException>(() => DnssecKeys.CreateDs(fixture.Key, 0, digest));
    }

    private sealed class AcceptingVerifier : IDnssecSignatureVerifier
    {
        internal int Calls { get; private set; }
        public bool VerifyHash(byte algorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature) { Calls++; return true; }
    }
}
