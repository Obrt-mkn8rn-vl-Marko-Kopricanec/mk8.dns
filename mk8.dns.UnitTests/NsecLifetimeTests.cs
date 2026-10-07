using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NsecLifetimeTests
{
    [Theory]
    [InlineData(0U)]
    [InlineData(17U)]
    [InlineData(300U)]
    public void NegativeTtlIncludesAuthenticatedSoaMinimum(uint minimum)
    {
        using var fixture = new NsecValidationFixture();
        var bytes = fixture.Soa.GetData();
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(bytes.Length - 4), minimum);
        var soa = new DnsRecord(fixture.Soa.Owner, 6, 300, bytes);
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        Assert.True(fixture.Validator.TryAuthenticateNoData(fixture.Keys, NsecValidationFixture.Question("a.example.", 28), [soa], [proof], [fixture.Sign(soa), fixture.Sign(proof)], out var ttl));
        Assert.Equal(minimum, ttl);
    }

    [Fact]
    public void NegativeTtlIncludesShortestDataAndSignatureAndKeyLeases()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        Assert.True(fixture.NoData("a.example.", 28, [proof.WithTtl(40)], out var ttl, [fixture.Sign(fixture.Soa).WithTtl(30), fixture.Sign(proof).WithTtl(20)]));
        Assert.Equal(20U, ttl);
        fixture.Clock.Advance(299.1);
        Assert.False(fixture.NoData("a.example.", 28, [proof], out _));
    }

    [Fact]
    public void ExpiredProofWindowCannotBeRescuedByLiveKeys()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        var signatures = new[] { fixture.Sign(fixture.Soa), fixture.Sign(proof, new DnssecSignatureWindow(90, 99)) };
        Assert.False(fixture.NoData("a.example.", 28, [proof], out _, signatures));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProviderWorkRechecksMonotonicLeaseAndAllWindows(bool wallJump)
    {
        using var fixture = new NsecValidationFixture();
        var expired = false;
        var provider = new DnssecChainFixture.CountingVerifier
        {
            AfterVerify = () =>
            {
                if (!expired) return;
                if (wallJump) fixture.Clock.SetWall(201);
                else fixture.Clock.Advance(300);
            },
        };
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        var keys = fixture.TrustWith(validator);
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        var signatures = new[] { fixture.Sign(fixture.Soa), fixture.Sign(proof, new DnssecSignatureWindow(100, 200)) };
        expired = true;
        Assert.False(validator.TryAuthenticateNoData(keys, NsecValidationFixture.Question("a.example.", 28), [fixture.Soa], [proof], signatures, out var ttl));
        Assert.Equal(0U, ttl);
    }

    [Fact]
    public void PartialSecondProviderWorkConservativelyAgesReturnedTtl()
    {
        using var fixture = new NsecValidationFixture();
        var advance = false;
        var provider = new DnssecChainFixture.CountingVerifier { AfterVerify = () => { if (advance) fixture.Clock.Advance(0.25); } };
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        var keys = fixture.TrustWith(validator);
        var proof = fixture.Nsec("a.example.", "z.example.", 1);
        advance = true;
        Assert.True(validator.TryAuthenticateNoData(keys, NsecValidationFixture.Question("a.example.", 28), [fixture.Soa], [proof], fixture.SignAll([proof]), out var ttl));
        Assert.Equal(299U, ttl);
    }

    [Fact]
    public void WildcardAndDelegationProofsAlsoRespectKeyExpiry()
    {
        using var fixture = new NsecValidationFixture();
        fixture.Clock.Advance(300);
        var delegation = fixture.Nsec("child.example.", "z.example.", 2);
        Assert.False(fixture.Validator.TryAuthenticateDsAbsence(fixture.Keys, delegation.Owner, [delegation], fixture.SignAll([delegation], soa: false), out _));
        Assert.False(fixture.Wildcard("*.example.", "b.example.", [fixture.Nsec("*.example.", "z.example.", 1)], out _));
    }
    [Fact]
    public void SelectedRootTrustIslandUsesTheRootCircularInterval()
    {
        using var fixture = new DnssecChainFixture();
        var root = DnsName.Parse(".");
        var key = fixture.ParentCskRecord.WithOwner(root);
        var keySig = DnssecChainFixture.Sign([key], key, fixture.ParentCsk);
        Assert.True(fixture.Validator.TryAuthenticateAnchor(new DnssecTrustAnchor(key), [key], [keySig], out var keys));
        var soa = AuthorityFixture.Zone().Soa.WithOwner(root);
        var denial = new DnsRecord(root, 47, 300, [0, .. NsecBitmap.Encode([2, 6, 48])]);
        var signatures = new[] { DnssecChainFixture.Sign([soa], key, fixture.ParentCsk), DnssecChainFixture.Sign([denial], key, fixture.ParentCsk) };
        Assert.True(fixture.Validator.TryAuthenticateNameError(keys, NsecValidationFixture.Question("missing."), [soa], [denial], signatures, out var ttl));
        Assert.Equal(60U, ttl);
    }

    [Fact]
    public void DenialSignatureSerialWrapBoundsTheReturnedLifetime()
    {
        using var fixture = new DnssecChainFixture();
        fixture.Clock.SetWall(0xfffffff5);
        var window = new DnssecSignatureWindow(0xfffffff0, 10);
        var keySig = DnssecChainFixture.Sign(fixture.ParentRecords, fixture.ParentCskRecord, fixture.ParentCsk, window);
        Assert.True(fixture.Validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), fixture.ParentRecords, [keySig], out var keys));
        var soa = AuthorityFixture.Zone().Soa;
        var denial = new DnsRecord(DnsName.Parse("a.example."), 47, 300, [.. DnsName.Parse("z.example.").ToWire(), .. NsecBitmap.Encode([1])]);
        var signatures = new[] { DnssecChainFixture.Sign([soa], fixture.ParentZskRecord, fixture.ParentZsk, window), DnssecChainFixture.Sign([denial], fixture.ParentZskRecord, fixture.ParentZsk, window) };
        Assert.True(fixture.Validator.TryAuthenticateNoData(keys, NsecValidationFixture.Question("a.example.", 28), [soa], [denial], signatures, out var ttl));
        Assert.Equal(21U, ttl);
        fixture.Clock.Advance(20);
        Assert.True(fixture.Validator.TryAuthenticateNoData(keys, NsecValidationFixture.Question("a.example.", 28), [soa], [denial], signatures, out ttl));
        Assert.Equal(1U, ttl);
        fixture.Clock.Advance(1);
        Assert.False(fixture.Validator.TryAuthenticateNoData(keys, NsecValidationFixture.Question("a.example.", 28), [soa], [denial], signatures, out _));
    }

}
