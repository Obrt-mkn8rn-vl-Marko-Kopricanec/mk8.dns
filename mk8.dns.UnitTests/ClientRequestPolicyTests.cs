using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientRequestPolicyTests
{
    // Documentation-range bytes and generic wildcard masks are finite policy vectors.
    [Theory]
    [InlineData("C0000200", 24, "C00002FF", true)]
    [InlineData("C0000200", 24, "C0000300", false)]
    [InlineData("C0000280", 25, "C00002FF", true)]
    [InlineData("C0000280", 25, "C000027F", false)]
    [InlineData("C0000202", 31, "C0000203", true)]
    [InlineData("C0000202", 31, "C0000204", false)]
    [InlineData("C0000201", 32, "C0000201", true)]
    [InlineData("C0000201", 32, "C0000202", false)]
    [InlineData("00000000", 0, "CB007101", true)]
    [InlineData("20010DB8000000000000000000000000", 32, "20010DB8FFFFFFFFFFFFFFFFFFFFFFFF", true)]
    [InlineData("20010DB8000000000000000000000000", 33, "20010DB87FFFFFFFFFFFFFFFFFFFFFFF", true)]
    [InlineData("20010DB8000000000000000000000000", 33, "20010DB8800000000000000000000000", false)]
    [InlineData("20010DB8000000000000000000000002", 127, "20010DB8000000000000000000000003", true)]
    [InlineData("20010DB8000000000000000000000002", 127, "20010DB8000000000000000000000004", false)]
    [InlineData("20010DB8000000000000000000000001", 128, "20010DB8000000000000000000000001", true)]
    [InlineData("20010DB8000000000000000000000001", 128, "C0000201", false)]
    public void CanonicalPrefixUsesExactFamilyAndBitBoundaries(string network, int prefix, string peer, bool allowed)
    {
        var grant = new DnssecClientNetwork(Convert.FromHexString(network), prefix);
        var policy = new DnssecClientAccessPolicy([grant]);
        Assert.Equal(allowed, policy.Allows(Convert.FromHexString(peer)));
        Assert.False(policy.AuthenticatedDataAllowed);
    }

    [Theory]
    [InlineData("C0000201", 24)]
    [InlineData("C0000200", -1)]
    [InlineData("C0000200", 33)]
    [InlineData("20010DB8000000000000000000000001", 127)]
    [InlineData("20010DB8000000000000000000000000", 129)]
    [InlineData("C00002", 24)]
    public void NoncanonicalOrInvalidGrantsRefuse(string network, int prefix)
        => Assert.ThrowsAny<ArgumentException>(() => new DnssecClientNetwork(Convert.FromHexString(network), prefix));

    [Fact]
    public void EmptyPolicyDeniesAndMappedPeerCannotBorrowEitherFamilyGrant()
    {
        Assert.False(new DnssecClientAccessPolicy([]).Allows([192, 0, 2, 1]));
        var all = new DnssecClientAccessPolicy([new DnssecClientNetwork(new byte[4], 0), new DnssecClientNetwork(new byte[16], 0)]);
        Assert.False(all.Allows(Convert.FromHexString("00000000000000000000FFFFC0000201")));
        Assert.False(all.Allows([])); Assert.False(all.Allows([1, 2, 3]));
        Assert.True(all.Allows(Convert.FromHexString("20010DB8000000000000000000000001")));
    }

    [Fact]
    public void CallerAndReturnedArraysCannotMutateGrants()
    {
        byte[] address = [192, 0, 2, 0];
        var network = new DnssecClientNetwork(address, 24);
        DnssecClientNetwork[] list = [network]; var policy = new DnssecClientAccessPolicy(list);
        address[0] = 198; network.GetAddress()[0] = 198; list[0] = new DnssecClientNetwork([198, 51, 100, 0], 24);
        Assert.True(policy.Allows([192, 0, 2, 1])); Assert.False(policy.Allows([198, 51, 100, 1]));
    }

    [Fact]
    public void DuplicateAndOversizedCollectionsCannotCreateAnUnboundedPolicy()
    {
        var grant = new DnssecClientNetwork([192, 0, 2, 0], 24);
        Assert.Throws<ArgumentException>(() => new DnssecClientAccessPolicy([grant, new DnssecClientNetwork([192, 0, 2, 0], 24)]));
        Assert.Throws<ArgumentException>(() => new DnssecClientAccessPolicy(Enumerable.Repeat(grant, 65)));
    }
}
