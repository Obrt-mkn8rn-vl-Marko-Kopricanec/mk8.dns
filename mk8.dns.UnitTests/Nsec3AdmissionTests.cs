using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class Nsec3AdmissionTests
{
    [Theory]
    [InlineData(0, 0)]
    [InlineData(0, 2)]
    [InlineData(1, 2)]
    [InlineData(1, 128)]
    [InlineData(2, 1)]
    [InlineData(3, 1)]
    [InlineData(4, 255)]
    [InlineData(5, 19)]
    [InlineData(5, 21)]
    public void UnsupportedOrMalformedHeaderCannotAuthorize(int offset, byte value)
    {
        using var fixture = new Nsec3ValidationFixture();
        var ring = Nsec3ValidationFixture.Ring(); var bytes = ring[0].GetData(); bytes[offset] = value;
        ring[0] = new DnsRecord(ring[0].Owner, 50, 300, bytes);
        Assert.False(fixture.NameError("new.example.", ring, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(25)]
    public void TruncatedDataFailsClosed(int length)
    {
        using var fixture = new Nsec3ValidationFixture();
        var hash = Nsec3ValidationFixture.Hash("example.");
        var proof = Nsec3ValidationFixture.Record(hash, hash, [2, 6]);
        var damaged = new DnsRecord(proof.Owner, 50, 300, proof.GetData().AsSpan(0, length));
        Assert.False(fixture.NoData("example.", 16, [damaged], out _));
    }

    [Theory]
    [InlineData("0.example.")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.example.")]
    [InlineData("0000000000000000000000000000000=.example.")]
    [InlineData("00000000000000000000000000000000.child.example.")]
    [InlineData("00000000000000000000000000000000.other.")]
    public void HashedOwnerMustBeOneExactBase32HexLabelUnderTheSelectedOrigin(string owner)
    {
        using var fixture = new Nsec3ValidationFixture();
        var ring = Nsec3ValidationFixture.Ring();
        var proof = ring[0].WithOwner(DnsName.Parse(owner));
        Assert.False(fixture.NameError("new.example.", [proof], out _, fixture.SignAll(ring)));
    }

    [Fact]
    public void MixedSaltsDuplicatesAndContradictoryCircularEdgesRefuse()
    {
        using var fixture = new Nsec3ValidationFixture();
        var ring = Nsec3ValidationFixture.Ring();
        var salted = Nsec3ValidationFixture.Ring(salt: [1]);
        Assert.False(fixture.NameError("new.example.", [ring[0], salted[0]], out _));
        Assert.False(fixture.NameError("new.example.", [ring[0], ring[0]], out _));
        var hash = Nsec3ValidationFixture.Hash("example.");
        var self = Nsec3ValidationFixture.Record(hash, hash, [2, 6]);
        Assert.False(fixture.NameError("new.example.", [self, .. ring.Where(record => !record.Owner.Equals(self.Owner))], out _));
        Assert.True(fixture.NameError("new.example.", [self], out _));
    }

    [Fact]
    public void EverySuppliedRecordAuthenticatesBeforeAnyEndpointIsUsed()
    {
        using var fixture = new Nsec3ValidationFixture();
        var ring = Nsec3ValidationFixture.Ring(); var signatures = fixture.SignAll(ring);
        var bytes = signatures[^1].GetData(); bytes[^1] ^= 1;
        signatures[^1] = new DnsRecord(signatures[^1].Owner, 46, 300, bytes);
        Assert.False(fixture.NameError("new.example.", ring, out _, signatures));
    }

    [Fact]
    public void EmptyExcessProofsAndMalformedOrMissingBitmapsRefuse()
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.NameError("new.example.", [], out _));
        var ring = Nsec3ValidationFixture.Ring();
        Assert.False(fixture.NameError("new.example.", [.. ring, .. ring], out _));
        var hash = Nsec3ValidationFixture.Hash("example.");
        var proof = Nsec3ValidationFixture.Record(hash, hash, []);
        foreach (var bitmap in new byte[][] { [0], [0, 0], [0, 1, 0], [1, 1, 1, 0, 1, 1], [0, 33] })
        {
            var damaged = new DnsRecord(proof.Owner, 50, 300, [.. proof.GetData(), .. bitmap]);
            Assert.False(fixture.NoData("example.", 16, [damaged], out _));
        }
    }

    [Fact]
    public void SoaBitmapMayDescribeOnlyTheActualApex()
    {
        using var fixture = new Nsec3ValidationFixture();
        var hash = Nsec3ValidationFixture.Hash("www.example.");
        Assert.False(fixture.NoData("www.example.", 28, [Nsec3ValidationFixture.Record(hash, hash, [6])], out _));
    }
}
