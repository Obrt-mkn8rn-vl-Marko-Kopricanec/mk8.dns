using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecSigningServiceTests
{
    [Fact]
    public void IntentFingerprintingNeverSignsOrDependsOnTimeButPublishedContentDoes()
    {
        using var key = DnssecFixture.Key();
        var counter = new DnssecFixture.CountingKey(key);
        var time = new SignedAuthorityFixture.Clock();
        var codec = SignedAuthorityFixture.Codec(counter, time);
        var zone = AuthorityFixture.Zone(DnssecFixture.A());
        var id = Guid.NewGuid();
        var firstIntent = codec.CompileIntent(id, 1, zone);
        time.Seconds = 2000;
        var secondIntent = codec.CompileIntent(id, 1, zone);
        Assert.Equal(firstIntent.ContentHash, secondIntent.ContentHash);
        Assert.Equal(0, counter.Calls);
        var first = codec.Compile(id, 1, zone);
        Assert.True(counter.Calls > 0);
        time.Seconds = 3000;
        var second = codec.Compile(id, 1, zone);
        Assert.False(string.Equals(first.ContentHash, second.ContentHash, StringComparison.Ordinal));
        Assert.Equal(firstIntent.ContentHash, codec.CompileIntent(id, 1, codec.Decode(second)).ContentHash);
    }

    [Fact]
    public void APolicyForAnotherExactOriginLeavesThisZoneUnsigned()
    {
        using var key = DnssecFixture.Key();
        var counter = new DnssecFixture.CountingKey(key);
        var codec = SignedAuthorityFixture.Codec(counter, new SignedAuthorityFixture.Clock());
        var zone = AuthorityFixture.ZoneAt("child.example.");
        var snapshot = codec.Compile(Guid.NewGuid(), 1, zone);
        Assert.False(codec.DecodeContents(snapshot).IsSigned);
        Assert.Equal(0, counter.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3599)]
    [InlineData(2_592_001)]
    [InlineData(uint.MaxValue)]
    public void InvalidStaticLifetimeIsRejectedBeforeSigning(uint lifetime)
    {
        using var key = DnssecFixture.Key();
        Assert.Throws<ArgumentException>(() => SignedAuthorityFixture.Codec(key, new SignedAuthorityFixture.Clock(), lifetime));
    }
}
