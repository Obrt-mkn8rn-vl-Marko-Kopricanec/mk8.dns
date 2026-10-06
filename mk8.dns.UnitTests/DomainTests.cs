using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DomainTests
{
    [Fact]
    public void NamesCompareUsingDnsAsciiCaseAndPreserveOctets()
    {
        Assert.Equal(DnsName.Parse("EXAMPLE.Org."), DnsName.Parse("example.org."));
        Assert.Equal("a\\046b.\\255.", DnsName.Parse("A\\.B.\\255.").ToString());
        Assert.NotEqual(DnsName.Parse("\\192."), DnsName.Parse("\\224."));
    }

    [Fact]
    public void WireAccessCannotMutateTheName()
    {
        var name = DnsName.Parse("a.");
        var bytes = name.ToWire();
        bytes[1] = (byte)'z';
        Assert.Equal("a.", name.ToString());
    }

    [Fact]
    public void SnapshotOwnsItsPayloadAndHash()
    {
        byte[] bytes = [1, 2, 3];
        var snapshot = new ZoneSnapshot(Guid.NewGuid(), DnsName.Parse("example.org."), 1, uint.MaxValue, bytes);
        bytes[0] = 99;
        var copy = snapshot.GetPayload();
        copy[1] = 99;
        Assert.Equal(new byte[] { 1, 2, 3 }, snapshot.GetPayload());
        Assert.Equal("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", snapshot.ContentHash);
    }

    [Fact]
    public void SnapshotRejectsInvalidIdentityRevisionAndPayloadBounds()
    {
        var origin = DnsName.Parse("example.org.");
        Assert.Throws<ArgumentException>(() => new ZoneSnapshot(Guid.Empty, origin, 1, 1, [1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ZoneSnapshot(Guid.NewGuid(), origin, 0, 1, [1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ZoneSnapshot(Guid.NewGuid(), origin, 1, 1, []));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ZoneSnapshot(Guid.NewGuid(), origin, 1, 1, new byte[ZoneSnapshot.MaximumPayloadBytes + 1]));
    }

    [Theory]
    [InlineData(0u, uint.MaxValue, true)]
    [InlineData(uint.MaxValue, 0u, false)]
    [InlineData(1u, 1u, false)]
    [InlineData(0x7FFFFFFFu, 0u, true)]
    [InlineData(0u, 0x7FFFFFFFu, false)]
    public void SerialsFollowModuloOrdering(uint candidate, uint current, bool expected) => Assert.Equal(expected, SoaSerial.IsNewer(candidate, current));

    [Fact]
    public void SerialWrapAndUndefinedHalfSpaceAreExplicit()
    {
        Assert.Equal(0u, SoaSerial.Next(uint.MaxValue));
        Assert.Throws<ArgumentException>(() => SoaSerial.IsNewer(0x80000000, 0));
    }
}
