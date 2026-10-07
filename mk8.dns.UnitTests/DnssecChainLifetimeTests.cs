using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecChainLifetimeTests
{
    [Fact]
    public void ParentDsKeyAndDataTtlsAllBoundTheFinalAuthenticatedLifetime()
    {
        using var fixture = new DnssecChainFixture();
        var parent = fixture.Trust();
        fixture.Clock.Advance(2.1);
        Assert.Equal(297u, fixture.Validator.GetRemainingTtl(parent));
        var ds = fixture.Delegation.WithTtl(80);
        var dsSig = fixture.DelegationSignature.WithTtl(40);
        var records = fixture.ChildRecords.Select(record => record.WithTtl(90)).ToArray();
        Assert.True(fixture.Validator.TryAuthenticateChild(parent, fixture.Child, [ds], [dsSig], records, [fixture.ChildSignature], out var child));
        Assert.Equal(40u, fixture.Validator.GetRemainingTtl(child));
        fixture.Clock.Advance(0.1);
        Assert.Equal(39u, fixture.Validator.GetRemainingTtl(child));
        var data = DnssecFixture.A("www.child.example.", ttl: 100);
        var sig = DnssecChainFixture.Sign([data], fixture.ChildZskRecord, fixture.ChildZsk).WithTtl(25);
        Assert.True(fixture.Validator.TryAuthenticateRrset(child, new DnsQuestion(data.Owner, 1, 1), [data], [sig], out var ttl));
        Assert.Equal(25u, ttl);
    }

    [Fact]
    public void ChildCannotOutliveAlreadyAgedParentEvidence()
    {
        using var fixture = new DnssecChainFixture();
        var parent = fixture.Trust();
        fixture.Clock.Advance(290);
        var child = fixture.AuthenticateChild(parent);
        Assert.Equal(10u, fixture.Validator.GetRemainingTtl(child));
        fixture.Clock.Advance(10);
        Assert.Equal(0u, fixture.Validator.GetRemainingTtl(parent));
        Assert.Equal(0u, fixture.Validator.GetRemainingTtl(child));
        Assert.False(fixture.Validator.TryAuthenticateChild(parent, fixture.Child, [fixture.Delegation], [fixture.DelegationSignature], fixture.ChildRecords, [fixture.ChildSignature], out _));
    }

    [Fact]
    public void SignatureWindowExpiryCapsBothLeasesAndData()
    {
        using var fixture = new DnssecChainFixture();
        var window = new DnssecSignatureWindow(100, 110);
        var signature = DnssecChainFixture.Sign(fixture.ParentRecords, fixture.ParentCskRecord, fixture.ParentCsk, window);
        Assert.True(fixture.Validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), fixture.ParentRecords, [signature], out var parent));
        Assert.Equal(10u, fixture.Validator.GetRemainingTtl(parent));
        var child = fixture.AuthenticateChild(parent);
        fixture.Clock.Advance(9);
        Assert.Equal(1u, fixture.Validator.GetRemainingTtl(child));
        fixture.Clock.Advance(1);
        Assert.Equal(0u, fixture.Validator.GetRemainingTtl(child));
    }

    [Fact]
    public void BackwardMonotonicSamplesCannotRefreshOrReviveExpiredLeases()
    {
        using var fixture = new DnssecChainFixture();
        var keys = fixture.Trust();
        fixture.Clock.Advance(10);
        Assert.Equal(290u, fixture.Validator.GetRemainingTtl(keys));
        fixture.Clock.SetMonotonic(0);
        fixture.Clock.SetWall(100);
        Assert.Equal(290u, fixture.Validator.GetRemainingTtl(keys));
        fixture.Clock.SetMonotonic(300);
        Assert.Equal(0u, fixture.Validator.GetRemainingTtl(keys));
        fixture.Clock.SetMonotonic(0);
        Assert.Equal(0u, fixture.Validator.GetRemainingTtl(keys));
    }

    [Theory]
    [InlineData(99)]
    [InlineData(10001)]
    public void CurrentWallTimeMustRemainWithinAllSignatureWindows(long seconds)
    {
        using var fixture = new DnssecChainFixture();
        var keys = fixture.AuthenticateChild();
        fixture.Clock.SetWall(seconds);
        Assert.Equal(0u, fixture.Validator.GetRemainingTtl(keys));
        var data = DnssecFixture.A("www.child.example.");
        var sig = DnssecChainFixture.Sign([data], fixture.ChildZskRecord, fixture.ChildZsk);
        Assert.False(fixture.Validator.TryAuthenticateRrset(keys, new DnsQuestion(data.Owner, 1, 1), [data], [sig], out _));
    }

    [Fact]
    public void ExpiryDuringTrustedProviderVerificationCannotPublishFreshLease()
    {
        using var fixture = new DnssecChainFixture();
        var provider = new DnssecChainFixture.CountingVerifier { AfterVerify = () => fixture.Clock.Advance(300) };
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        Assert.False(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), fixture.ParentRecords, [fixture.ParentSignature], out var keys));
        Assert.Null(keys);
        Assert.Equal(1, provider.Calls);
    }

    [Fact]
    public void ForwardWallJumpDuringVerificationRechecksAbsoluteExpiry()
    {
        using var fixture = new DnssecChainFixture();
        var provider = new DnssecChainFixture.CountingVerifier { AfterVerify = () => fixture.Clock.SetWall(10000) };
        var validator = new DnssecChainValidator(provider, fixture.Clock);
        Assert.False(validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), fixture.ParentRecords, [fixture.ParentSignature], out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void ZeroTtlKeyEvidenceCannotBeRetainedAsLiveTrust(int selector)
    {
        using var fixture = new DnssecChainFixture();
        var records = selector == 0 ? fixture.ParentRecords.Select(record => record.WithTtl(0)).ToArray() : fixture.ParentRecords;
        var signature = selector == 1 ? fixture.ParentSignature.WithTtl(0) : fixture.ParentSignature;
        Assert.False(fixture.Validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), records, [signature], out _));
    }

    [Fact]
    public void ZeroTtlDataCanAuthenticateWithoutReceivingCacheLifetime()
    {
        using var fixture = new DnssecChainFixture();
        var keys = fixture.Trust();
        var data = DnssecFixture.A(ttl: 0);
        var signature = DnssecChainFixture.Sign([data], fixture.ParentZskRecord, fixture.ParentZsk);
        Assert.True(fixture.Validator.TryAuthenticateRrset(keys, new DnsQuestion(data.Owner, 1, 1), [data], [signature], out var ttl));
        Assert.Equal(0u, ttl);
    }

    [Fact]
    public void SerialTimeWrapAuthenticatesButDoesNotExtendExpiry()
    {
        using var fixture = new DnssecChainFixture();
        fixture.Clock.SetWall(0xfffffff5);
        var window = new DnssecSignatureWindow(0xfffffff0, 10);
        var signature = DnssecChainFixture.Sign(fixture.ParentRecords, fixture.ParentCskRecord, fixture.ParentCsk, window);
        Assert.True(fixture.Validator.TryAuthenticateAnchor(new DnssecTrustAnchor(fixture.ParentCskRecord), fixture.ParentRecords, [signature], out var keys));
        Assert.Equal(21u, fixture.Validator.GetRemainingTtl(keys));
        fixture.Clock.Advance(20);
        Assert.Equal(1u, fixture.Validator.GetRemainingTtl(keys));
        fixture.Clock.Advance(1);
        Assert.Equal(0u, fixture.Validator.GetRemainingTtl(keys));
    }
}
