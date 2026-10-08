using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class Nsec3LifetimeTests
{
    [Fact]
    public void AllProofsAndNegativeSoaMinimumBoundLifetime()
    {
        using var fixture = new Nsec3ValidationFixture();
        var ring = Nsec3ValidationFixture.Ring(); ring[0] = ring[0].WithTtl(7);
        Assert.True(fixture.NameError("new.example.", ring, out var ttl));
        Assert.Equal(7u, ttl);
        fixture.Clock.Advance(1.1);
        Assert.True(fixture.NameError("new.example.", ring.Select(record => record.WithTtl(0)).ToArray(), out ttl));
        Assert.Equal(0u, ttl);
    }

    [Fact]
    public void ForeignOrExpiredKeyContextNeverAuthorizesEvenValidProofs()
    {
        using var fixture = new Nsec3ValidationFixture();
        var other = new DnssecChainValidator(DnssecFixture.Verifier, fixture.Clock); var ring = Nsec3ValidationFixture.Ring();
        Assert.False(other.TryAuthenticateNsec3NameError(fixture.Keys, NsecValidationFixture.Question("new.example."),
            [fixture.Soa], ring, fixture.SignAll(ring), out _));
        fixture.Clock.Advance(301);
        Assert.False(fixture.NameError("new.example.", ring, out _));
        fixture.Clock.SetMonotonic(0); fixture.Clock.SetWall(100);
        Assert.False(fixture.NameError("new.example.", ring, out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FinalProviderWorkCannotOutliveProofOrInheritedKeyWindow(bool elapsedExpiry)
    {
        using var fixture = new Nsec3ValidationFixture();
        var armed = false;
        var provider = new DnssecChainFixture.CountingVerifier
        {
            AfterVerify = () =>
        {
            if (!armed) return;
            if (elapsedExpiry) fixture.Clock.SetMonotonic(301);
            else fixture.Clock.SetWall(10001);
        }
        };
        var validator = new DnssecChainValidator(provider, fixture.Clock); var keys = fixture.TrustWith(validator);
        var ring = Nsec3ValidationFixture.Ring();
        Assert.True(validator.TryAuthenticateNsec3NameError(keys, NsecValidationFixture.Question("new.example."),
            [fixture.Soa], ring, fixture.SignAll(ring), out _));
        armed = true;
        Assert.False(validator.TryAuthenticateNsec3NameError(keys, NsecValidationFixture.Question("new.example."),
            [fixture.Soa], ring, fixture.SignAll(ring), out var ttl));
        Assert.Equal(0u, ttl);
    }

    [Fact]
    public void NegativeSignatureWindowExpiryCapsTtl()
    {
        using var fixture = new Nsec3ValidationFixture();
        var ring = Nsec3ValidationFixture.Ring();
        var signatures = ring.Prepend(fixture.Soa).Select(record => fixture.Sign(record, new DnssecSignatureWindow(99, 103))).ToArray();
        Assert.True(fixture.NameError("new.example.", ring, out var ttl, signatures)); Assert.Equal(3u, ttl);
        fixture.Clock.SetWall(104);
        Assert.False(fixture.NameError("new.example.", ring, out _, signatures));
    }
}
