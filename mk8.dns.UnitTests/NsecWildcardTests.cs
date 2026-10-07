using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NsecWildcardTests
{
    [Theory]
    [InlineData("b.example.")]
    [InlineData("deep.b.example.")]
    public void ValidExpansionNeedsAuthenticatedClosestAndNextCloserAbsence(string question)
    {
        using var fixture = new NsecValidationFixture();
        Assert.True(fixture.Wildcard("*.example.", question, [fixture.Nsec("*.example.", "z.example.", 1)], out var ttl));
        Assert.Equal(300U, ttl);
    }

    [Fact]
    public void ExistingEmptyNonterminalPreventsHigherWildcardExpansion()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", "a.example.", [fixture.Nsec("*.example.", "host.a.example.", 1)], out _));
    }

    [Fact]
    public void CloserEncloserPreventsHigherWildcardExpansion()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", "x.a.example.", [fixture.Nsec("host.a.example.", "z.example.", 1)], out _));
    }

    [Fact]
    public void ClosestEmptyNonterminalCanSupplyItsOwnWildcard()
    {
        using var fixture = new NsecValidationFixture();
        Assert.True(fixture.Wildcard("*.a.example.", "bar.a.example.", [fixture.Nsec("*.a.example.", "host.a.example.", 1)], out _));
    }

    [Fact]
    public void ExistingCloserNamePreventsExpansion()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", "a.example.", [fixture.Nsec("a.example.", "z.example.", 1)], out _));
    }

    [Theory]
    [InlineData((ushort)1, false)]
    [InlineData((ushort)28, true)]
    [InlineData((ushort)43, false)]
    public void WildcardNoDataNeedsWildcardOwnerBitmap(ushort type, bool expected)
    {
        using var fixture = new NsecValidationFixture();
        Assert.Equal(expected, fixture.NoData("b.example.", type, [fixture.Nsec("*.example.", "z.example.", 1)], out _));
    }

    [Fact]
    public void WildcardCnameCannotBeStrippedIntoNoData()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.NoData("b.example.", 28, [fixture.Nsec("*.example.", "z.example.", 5)], out _));
        Assert.True(fixture.Wildcard("*.example.", "b.example.", [fixture.Nsec("*.example.", "z.example.", 5)], out _, type: 5));
    }

    [Fact]
    public void WildcardDataBitmapMustAgreeIfSupplied()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", "b.example.", [fixture.Nsec("*.example.", "z.example.", 16)], out _));
    }

    [Fact]
    public void APositiveSignatureAloneCannotAuthenticateExpansion()
    {
        using var fixture = new NsecValidationFixture();
        var records = fixture.Expanded("*.example.", "b.example.");
        Assert.False(fixture.Validator.TryAuthenticateWildcard(fixture.Keys, NsecValidationFixture.Question("b.example."), [records[0]], [], [records[1]], out _));
    }

    [Fact]
    public void ExactPositiveSignatureCannotMasqueradeAsWildcard()
    {
        using var fixture = new NsecValidationFixture();
        var record = DnssecFixture.A("b.example.");
        var proof = fixture.Nsec("*.example.", "z.example.", 1);
        Assert.False(fixture.Validator.TryAuthenticateWildcard(fixture.Keys, NsecValidationFixture.Question("b.example."), [record], [proof], [fixture.Sign(record), fixture.Sign(proof)], out _));
    }

    [Fact]
    public void ExistingExactApiStillRefusesExpandedWildcard()
    {
        using var fixture = new NsecValidationFixture();
        var records = fixture.Expanded("*.example.", "b.example.");
        Assert.False(fixture.Validator.TryAuthenticateRrset(fixture.Keys, NsecValidationFixture.Question("b.example."), [records[0]], [records[1]], out _));
    }

    [Theory]
    [InlineData((ushort)2)]
    [InlineData((ushort)39)]
    public void DelegationAndDnameCannotSupplyDescendantWildcard(ushort type)
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", "b.a.example.", [fixture.Nsec("a.example.", "z.example.", type)], out _));
    }

    [Fact]
    public void SynthesizedNsecCannotReplaceLiteralWildcardProof()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("*.example.", "z.example.", 1);
        var owner = DnsName.Parse("b.example.");
        var expanded = proof.WithOwner(owner);
        Assert.False(fixture.NoData("b.example.", 28, [expanded], out _, [fixture.Sign(fixture.Soa), fixture.Sign(proof).WithOwner(owner)]));
    }
    [Fact]
    public void EmptyWildcardNonterminalCanProduceNoData()
    {
        using var fixture = new NsecValidationFixture();
        Assert.True(fixture.NoData("b.example.", 28,
            [fixture.Nsec("example.", "host.*.example.", 6), fixture.Nsec("host.*.example.", "z.example.", 1)], out _));
        Assert.False(fixture.NameError("b.example.",
            [fixture.Nsec("example.", "host.*.example.", 6), fixture.Nsec("host.*.example.", "z.example.", 1)], out _));
    }

}
