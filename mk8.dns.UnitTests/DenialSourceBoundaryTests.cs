using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DenialSourceBoundaryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NonRootApexWithoutItsExactHashRefusesFiniteNegativeProof(bool nameError)
    {
        using var fixture = new Nsec3ValidationFixture();
        var hash = Nsec3ValidationFixture.Hash("www.example.");
        var proof = Nsec3ValidationFixture.Record(hash, hash, [1, 46]);
        var accepted = nameError ? fixture.NameError("example.", [proof], out var ttl)
            : fixture.NoData("example.", 16, [proof], out ttl);
        Assert.False(accepted);
        Assert.Equal(0u, ttl);
    }

    [Fact]
    public void AuthenticatedIntervalCannotDenyTheExpandedWildcardSource()
    {
        using var fixture = new NsecValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", "b.example.",
            [fixture.Nsec("example.", "z.example.", 2, 6)], out var ttl));
        Assert.Equal(0u, ttl);
        Assert.True(fixture.Wildcard("*.example.", "b.example.",
            [fixture.Nsec("*.example.", "z.example.", 1)], out ttl));
        Assert.Equal(300u, ttl);
    }
}
