using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class Nsec3WildcardTests
{
    [Theory]
    [InlineData("new.example.")]
    [InlineData("deeper.new.example.")]
    public void SignedExpansionAndNextCloserAbsenceAuthenticate(string name)
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.True(fixture.Wildcard("*.example.", name, Nsec3ValidationFixture.Ring(wildcard: true), out var ttl));
        Assert.InRange(ttl, 1u, 300u);
    }

    [Fact]
    public void MinimalPositiveProofDoesNotRequireClosestEncloserMatch()
    {
        using var fixture = new Nsec3ValidationFixture();
        var proof = Cover(Nsec3ValidationFixture.Ring(wildcard: true), "new.example.");
        Assert.True(fixture.Wildcard("*.example.", "new.example.", [proof], out _));
    }

    [Theory]
    [InlineData("www.example.")]
    [InlineData("child.example.")]
    [InlineData("new.child.example.")]
    [InlineData("new.alias.example.")]
    [InlineData("new.empty.example.")]
    public void ExistingNamesCutsDnameAndCloserEnclosersBlockExpansion(string name)
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", name, Nsec3ValidationFixture.Ring(wildcard: true), out _));
    }

    [Fact]
    public void OptOutCoverCannotAuthenticateWildcardData()
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", "new.example.", Nsec3ValidationFixture.Ring(wildcard: true, optOut: true), out _));
    }

    [Fact]
    public void ContradictoryWildcardAbsenceCannotAuthorizeSignedExpansion()
    {
        using var fixture = new Nsec3ValidationFixture();
        Assert.False(fixture.Wildcard("*.example.", "new.example.", Nsec3ValidationFixture.Ring(), out _));
    }

    [Fact]
    public void CorruptedWildcardSignatureCannotBeReplacedByDenialSignatures()
    {
        using var fixture = new Nsec3ValidationFixture();
        var records = fixture.Expanded("*.example.", "new.example.");
        var bytes = records[1].GetData(); bytes[^1] ^= 1;
        var denial = Nsec3ValidationFixture.Ring(wildcard: true);
        Assert.False(fixture.Validator.TryAuthenticateNsec3Wildcard(fixture.Keys, NsecValidationFixture.Question("new.example."),
            [records[0]], denial, [new DnsRecord(records[1].Owner, 46, 300, bytes), .. fixture.SignAll(denial, soa: false)], out _));
    }

    internal static DnsRecord Cover(DnsRecord[] ring, string name)
    {
        var hash = Nsec3ValidationFixture.Hash(name);
        return ring.Single(record =>
        {
            var owner = Decode(record.Owner.ToString().Split('.')[0]);
            var next = record.GetData().AsSpan(6, 20).ToArray();
            var low = owner.AsSpan().SequenceCompareTo(hash); var high = hash.AsSpan().SequenceCompareTo(next);
            return low != 0 && high != 0 && (owner.AsSpan().SequenceCompareTo(next) < 0 ? low < 0 && high < 0 : low < 0 || high < 0);
        });
    }

    private static byte[] Decode(string label)
    {
        const string alphabet = "0123456789abcdefghijklmnopqrstuv";
        var bytes = new byte[20]; var bits = 0; var buffer = 0; var index = 0;
        foreach (var value in label) { buffer = (buffer << 5) | alphabet.IndexOf(value, StringComparison.Ordinal); bits += 5; if (bits >= 8) { bits -= 8; bytes[index++] = (byte)(buffer >> bits); } }
        return bytes;
    }
}
