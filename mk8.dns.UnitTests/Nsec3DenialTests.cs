using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class Nsec3DenialTests
{
    [Theory]
    [InlineData("absent.example.")]
    [InlineData("deeper.absent.example.")]
    [InlineData("absent.empty.example.")]
    [InlineData("ABSENT.EXAMPLE.")]
    public void AuthenticatedClosestEncloserAndWildcardAbsenceProveNameError(string name)
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.True(fixture.NameError(name, Nsec3ValidationFixture.Ring(), out var ttl));
        Assert.InRange(ttl, 1u, 300u);
    }

    [Theory]
    [InlineData("www.example.", 28)]
    [InlineData("empty.example.", 1)]
    [InlineData("example.", 16)]
    [InlineData("child.example.", 43)]
    public void ExactTypeAbsenceIncludesEmptyNonterminals(string name, ushort type)
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.True(fixture.NoData(name, type, Nsec3ValidationFixture.Ring(), out _));
    }

    [Theory]
    [InlineData("www.example.")]
    [InlineData("empty.example.")]
    [InlineData("child.example.")]
    [InlineData("below.child.example.")]
    [InlineData("below.alias.example.")]
    public void ExistingNamesAndCutOrDnameDescendantsCannotBeNameError(string name)
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.NameError(name, Nsec3ValidationFixture.Ring(), out var ttl));
        Assert.Equal(0u, ttl);
    }

    [Theory]
    [InlineData("www.example.", 1)]
    [InlineData("child.example.", 1)]
    [InlineData("below.child.example.", 28)]
    [InlineData("below.alias.example.", 28)]
    [InlineData("example.", 43)]
    [InlineData("missing.example.", 43)]
    public void ExistingTypesOrWrongSideOfCutCannotBeNoData(string name, ushort type)
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.NoData(name, type, Nsec3ValidationFixture.Ring(), out _));
    }

    [Fact]
    public void WildcardNoDataRequiresTheExactWildcardBitmap()
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.True(fixture.NoData("new.example.", 28, Nsec3ValidationFixture.Ring(wildcard: true), out _));
        Assert.False(fixture.NoData("new.example.", 1, Nsec3ValidationFixture.Ring(wildcard: true), out _));
        Assert.False(fixture.NameError("new.example.", Nsec3ValidationFixture.Ring(wildcard: true), out _));
        Assert.False(fixture.NoData("new.example.", 28, Nsec3ValidationFixture.Ring(), out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(255)]
    public void SaltIsBoundedWireDataAndMustMatchEveryProof(int saltLength)
    {
        using var fixture = new Nsec3ValidationFixture();
        var salt = Enumerable.Range(0, saltLength).Select(value => (byte)value).ToArray();
        Assert.True(fixture.NameError("new.example.", Nsec3ValidationFixture.Ring(salt: salt), out _));
    }

    [Fact]
    public void OptOutCoverCannotAuthenticateOrdinaryAbsence()
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.NameError("new.example.", Nsec3ValidationFixture.Ring(optOut: true), out _));
        Assert.False(fixture.NoData("new.example.", 28, Nsec3ValidationFixture.Ring(wildcard: true, optOut: true), out _));
        Assert.True(fixture.NoData("www.example.", 28, Nsec3ValidationFixture.Ring(optOut: true), out _));
    }

    [Fact]
    public void CnameBitmapCannotBeStrippedIntoNoData()
    {
        using var fixture = new Nsec3ValidationFixture();
        var hash = Nsec3ValidationFixture.Hash("example.");
        var proof = Nsec3ValidationFixture.Record(hash, hash, [2, 5, 6]);
        Assert.False(fixture.NoData("example.", 16, [proof], out _));
    }

    [Fact]
    public void UppercaseBase32HexOwnerHasTheSameProofMeaning()
    {
        using var fixture = new Nsec3ValidationFixture();
        var proofs = Nsec3ValidationFixture.Ring().Select(record => record.WithOwner(DnsName.Parse(record.Owner.ToString().ToUpperInvariant()))).ToArray();
        Assert.True(fixture.NameError("new.example.", proofs, out _));
    }
}
