using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NsecDenialTests
{
    [Theory]
    [InlineData("b.example.")]
    [InlineData("foo.b.example.")]
    [InlineData("zzz.example.")]
    [InlineData("a\\000.example.")]
    public void NameErrorNeedsQueryAndWildcardAbsence(string question)
    {
        using var fixture = new NsecValidationFixture();
        var first = fixture.Nsec("example.", "a.example.", 2, 6, 48);
        var middle = fixture.Nsec("a.example.", "z.example.", 1);
        var last = fixture.Nsec("z.example.", "example.", 1);
        Assert.True(fixture.NameError(question, [first, middle, last], out var ttl));
        Assert.Equal(300U, ttl);
    }

    [Theory]
    [InlineData("example.")]
    [InlineData("a.example.")]
    [InlineData("z.example.")]
    public void ExistingEndpointsCannotBeNameErrors(string question)
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.NameError(question, [fixture.Nsec("example.", "a.example.", 6), fixture.Nsec("a.example.", "z.example.", 1), fixture.Nsec("z.example.", "example.", 1)], out _));
    }

    [Fact]
    public void QueryCoverageAloneDoesNotDenyWildcard()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.NameError("b.example.", [fixture.Nsec("a.example.", "z.example.", 1)], out _));
    }

    [Fact]
    public void ExistingWildcardCannotBeNameError()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.NameError("b.example.", [fixture.Nsec("*.example.", "z.example.", 1), fixture.Nsec("z.example.", "example.", 1)], out _));
    }

    [Fact]
    public void EmptyNonterminalIsNoDataRatherThanNameError()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "host.ent.example.", 1);
        Assert.True(fixture.NoData("ent.example.", 28, [proof], out _));
        Assert.False(fixture.NameError("ent.example.", [proof], out _));
    }

    [Fact]
    public void DescendantOfEmptyNonterminalUsesThatClosestEncloser()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "host.ent.example.", 1);
        Assert.True(fixture.NameError("bar.ent.example.", [proof], out _));
    }

    [Theory]
    [InlineData((ushort)28, true)]
    [InlineData((ushort)1, false)]
    [InlineData((ushort)46, false)]
    [InlineData((ushort)47, false)]
    public void ExactNoDataChecksTypeIncludingImplicitSecurityRecords(ushort type, bool expected)
    {
        using var fixture = new NsecValidationFixture();
        Assert.Equal(expected, fixture.NoData("a.example.", type, [fixture.Nsec("a.example.", "z.example.", 1)], out _));
    }

    [Fact]
    public void MissingSecurityBitsDoNotProveSecurityTypesAbsent()
    {
        using var fixture = new NsecValidationFixture();
        var proof = new DnsRecord(DnsName.Parse("a.example."), 47, 300, [.. DnsName.Parse("z.example.").ToWire(), .. Mk8.Dns.Engine.Dnssec.NsecBitmap.Encode([1])]);
        Assert.True(fixture.NoData("a.example.", 28, [proof], out _));
        Assert.False(fixture.NoData("a.example.", 46, [proof], out _));
        Assert.False(fixture.NoData("a.example.", 47, [proof], out _));
    }

    [Fact]
    public void CnameCannotBeStrippedIntoNoData()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.NoData("a.example.", 28, [fixture.Nsec("a.example.", "z.example.", 5)], out _));
    }

    [Theory]
    [InlineData((ushort)2)]
    [InlineData((ushort)39)]
    public void DescendantsOfDelegationOrDnameCannotBeDenied(ushort type)
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("a.example.", "z.example.", type);
        Assert.False(fixture.NameError("b.a.example.", [fixture.Nsec("example.", "a.example.", 6), proof], out _));
        Assert.False(fixture.NoData("b.a.example.", 28, [proof], out _));
    }

    [Fact]
    public void DnameAtExactOwnerDoesNotBlockOrdinaryNoData()
    {
        using var fixture = new NsecValidationFixture();
        Assert.True(fixture.NoData("a.example.", 28, [fixture.Nsec("a.example.", "z.example.", 39)], out _));
    }

    [Fact]
    public void DelegationCanProveOnlyParentSideDsNoData()
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("child.example.", "z.example.", 2);
        Assert.False(fixture.NoData("child.example.", 28, [proof], out _));
        Assert.True(fixture.NoData("child.example.", 43, [proof], out _));
        Assert.True(fixture.Validator.TryAuthenticateDsAbsence(fixture.Keys, proof.Owner, [proof], fixture.SignAll([proof], soa: false), out _));
    }

    [Theory]
    [InlineData((ushort)1)]
    [InlineData((ushort)43)]
    [InlineData((ushort)6)]
    [InlineData((ushort)5)]
    public void DsAbsenceRequiresActualUnsignedDelegationBitmap(ushort extra)
    {
        using var fixture = new NsecValidationFixture();
        var proof = fixture.Nsec("child.example.", "z.example.", extra == 1 ? extra : (ushort)2, extra);
        Assert.False(fixture.Validator.TryAuthenticateDsAbsence(fixture.Keys, proof.Owner, [proof], fixture.SignAll([proof], soa: false), out _));
    }

    [Fact]
    public void ChildSideApexProofCannotEstablishParentDsAbsence()
    {
        using var fixture = new NsecValidationFixture();
        var child = fixture.Child;
        var proof = fixture.Nsec("child.example.", "child.example.", 2, 6, 48);
        Assert.False(fixture.Validator.TryAuthenticateDsAbsence(child, child.Origin, [proof], fixture.SignAll([proof], soa: false), out _));
        Assert.False(fixture.NoData("example.", 43, [fixture.Nsec("example.", "z.example.", 2, 6, 48)], out _));
    }

    [Fact]
    public void AOneNodeApexRingCanProveNameError()
    {
        using var fixture = new NsecValidationFixture();
        Assert.True(fixture.NameError("missing.example.", [fixture.Nsec("example.", "example.", 2, 6, 48)], out _));
    }
}
