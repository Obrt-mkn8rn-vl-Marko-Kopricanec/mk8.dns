using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class Nsec3DelegationTests
{
    [Fact]
    public void ExactParentDelegationProvesDsAbsenceWithoutOptOutMarker()
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.True(fixture.Ds("child.example.", Nsec3ValidationFixture.Ring(), out var ttl, out var optOut));
        Assert.False(optOut); Assert.InRange(ttl, 1u, 300u);
    }

    [Theory]
    [InlineData("new.example.")]
    [InlineData("new.empty.example.")]
    public void MissingActualDelegationRequiresClosestEncloserAndOptOutCover(string name)
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.Ds(name, Nsec3ValidationFixture.Ring(), out _, out _));
        Assert.True(fixture.Ds(name, Nsec3ValidationFixture.Ring(optOut: true), out var ttl, out var optOut));
        Assert.True(optOut); Assert.InRange(ttl, 1u, 300u);
    }

    [Theory]
    [InlineData("example.")]
    [InlineData("www.example.")]
    [InlineData("empty.example.")]
    [InlineData("below.child.example.")]
    [InlineData("below.alias.example.")]
    [InlineData("outside.")]
    public void NondelegationApexForeignAndOccludedNamesCannotBecomeDelegationMarkers(string name)
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.Ds(name, Nsec3ValidationFixture.Ring(optOut: true), out var ttl, out var optOut));
        Assert.Equal(0u, ttl); Assert.False(optOut);
    }

    [Fact]
    public void PresentDsCnameOrDnameCannotBecomeDsAbsence()
    {
        using var fixture = new Nsec3ValidationFixture();
        foreach (var type in new ushort[] { 43, 5, 39 })
        {
            var hash = Nsec3ValidationFixture.Hash("child.example.");
            var proof = Nsec3ValidationFixture.Record(hash, hash, [2, type]);
            Assert.False(fixture.Ds("child.example.", [proof], out _, out _));
        }
    }
}
