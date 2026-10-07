using System.Net;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CookieServiceTests
{
    [Theory]
    [InlineData("e5e973e5a6b2a43f48e7dc849e37bfcf", "198.51.100.100", 1559731985L, "2464c4abcf10c957010000005cf79f111f8130c3eee29480")]
    [InlineData("e5e973e5a6b2a43f48e7dc849e37bfcf", "198.51.100.100", 1559734385L, "2464c4abcf10c957010000005cf7a871d4a564a1442aca77")]
    [InlineData("e5e973e5a6b2a43f48e7dc849e37bfcf", "203.0.113.203", 1559734700L, "fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e")]
    [InlineData("445536bcd2513298075a5d379663c962", "2001:db8:220:1:59de:d0f4:8769:82b8", 1559741961L, "22681ab97d52c298010000005cf7c609a6bb79d16625507a")]
    public void Rfc9018CreationVectorsMatchExactOctets(string secret, string address, long timestamp, string expected)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(expected);
        var clock = new CookieClock(timestamp);
        using var service = new DnsCookieService(Convert.FromHexString(secret), clock.GetUtcNow().AddDays(-1), null, null, clock);
        var bytes = Convert.FromHexString(expected);
        Assert.Equal(bytes, service.Create(bytes.AsSpan(0, 8), IPAddress.Parse(address).GetAddressBytes()));
        Assert.True(service.Validate(bytes, IPAddress.Parse(address).GetAddressBytes()));
    }

    [Fact]
    public void ReservedBytesAreAuthenticatedWithoutRequiringZero()
    {
        var clock = new CookieClock(1559728000);
        using var service = new DnsCookieService(Convert.FromHexString("e5e973e5a6b2a43f48e7dc849e37bfcf"), clock.GetUtcNow().AddDays(-1), null, null, clock);
        var cookie = Convert.FromHexString("fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5");
        var peer = IPAddress.Parse("203.0.113.203").GetAddressBytes();
        Assert.True(service.Validate(cookie, peer));
        cookie[10] ^= 1;
        Assert.False(service.Validate(cookie, peer));
    }

    [Fact]
    public void RfcIpv6RolloverAcceptsOldMacAndIssuesNewMac()
    {
        var clock = new CookieClock(1559741961);
        var created = clock.GetUtcNow().AddDays(-1);
        using var service = new DnsCookieService(Convert.FromHexString("445536bcd2513298075a5d379663c962"), created,
            Convert.FromHexString("dd3bdf9344b678b185a6f5cb60fca715"), created, clock);
        var old = Convert.FromHexString("22681ab97d52c298010000005cf7c57926556bd0934c72f8");
        var peer = IPAddress.Parse("2001:db8:220:1:59de:d0f4:8769:82b8").GetAddressBytes();
        Assert.True(service.Validate(old, peer));
        Assert.Equal(Convert.FromHexString("22681ab97d52c298010000005cf7c609a6bb79d16625507a"), service.Create(old.AsSpan(0, 8), peer));
    }

    [Theory]
    [InlineData(-301, false)]
    [InlineData(-300, true)]
    [InlineData(0, true)]
    [InlineData(3600, true)]
    [InlineData(3601, false)]
    [InlineData(2147483648L, false)]
    public void TimestampWindowUsesSerialArithmeticAcrossUintWrap(long age, bool expected)
    {
        var clock = new CookieClock(4294967290);
        using var service = DnsCookieService.CreateEphemeral(clock);
        var peer = new byte[] { 192, 0, 2, 1 };
        var cookie = service.Create(new byte[8], peer);
        Assert.NotNull(cookie);
        clock.Advance(age);
        Assert.Equal(expected, service.Validate(cookie, peer));
    }

    [Fact]
    public void AddressClientCookieVersionLengthAndHashCannotBeSubstituted()
    {
        var clock = new CookieClock(1559731985);
        var key = Convert.FromHexString("e5e973e5a6b2a43f48e7dc849e37bfcf");
        using var service = new DnsCookieService(key, clock.GetUtcNow(), null, null, clock);
        var cookie = Convert.FromHexString("2464c4abcf10c957010000005cf79f111f8130c3eee29480");
        var peer = IPAddress.Parse("198.51.100.100").GetAddressBytes();
        key.AsSpan().Clear();
        Assert.True(service.Validate(cookie, peer));
        Assert.False(service.Validate(cookie, IPAddress.Parse("198.51.100.101").GetAddressBytes()));
        Assert.False(service.Validate(cookie, IPAddress.Parse("::ffff:198.51.100.100").GetAddressBytes()));
        Assert.False(service.Validate(cookie.Concat(new byte[12]).ToArray(), peer));
        foreach (var index in new[] { 0, 8, 12, 16, 23 })
        {
            var changed = (byte[])cookie.Clone();
            changed[index] ^= 1;
            Assert.False(service.Validate(changed, peer));
        }
    }

    [Fact]
    public void ThreeStageSecretRolloverPreservesThenRetiresOldProofs()
    {
        var clock = new CookieClock(1559731985);
        var created = clock.GetUtcNow();
        var first = Convert.FromHexString("e5e973e5a6b2a43f48e7dc849e37bfcf");
        var next = Convert.FromHexString("445536bcd2513298075a5d379663c962");
        var peer = new byte[] { 192, 0, 2, 1 };
        using var stageOne = new DnsCookieService(first, created, next, created, clock);
        using var stageTwo = new DnsCookieService(next, created, first, created, clock);
        using var stageThree = new DnsCookieService(next, created, null, null, clock);
        var old = stageOne.Create(new byte[8], peer);
        var current = stageTwo.Create(new byte[8], peer);
        Assert.NotNull(old);
        Assert.NotNull(current);
        Assert.True(stageOne.Validate(current, peer));
        Assert.True(stageTwo.Validate(old, peer));
        Assert.True(stageThree.Validate(current, peer));
        Assert.False(stageThree.Validate(old, peer));
        Assert.NotEqual(old, current);
    }

    [Fact]
    public void DatedStaticSecretsExpireWhileEphemeralSecretsRotateAndDisposalIsTerminal()
    {
        var clock = new CookieClock(1559731985);
        using var service = new DnsCookieService(new byte[16], clock.GetUtcNow(), null, null, clock);
        using var ephemeral = DnsCookieService.CreateEphemeral(clock);
        clock.Advance(36 * 86400);
        Assert.False(service.IsAvailable);
        Assert.Null(service.Create(new byte[8], new byte[4]));
        Assert.True(ephemeral.IsAvailable);
        var cookie = ephemeral.Create(new byte[8], new byte[16]);
        Assert.NotNull(cookie);
        Assert.True(ephemeral.Validate(cookie, new byte[16]));
        ephemeral.Dispose();
        ephemeral.Dispose();
        Assert.False(ephemeral.IsAvailable);
        Assert.Throws<ObjectDisposedException>(() => ephemeral.Create(new byte[8], new byte[4]));
        Assert.Throws<ObjectDisposedException>(() => ephemeral.Validate(cookie, new byte[16]));
        Assert.Throws<ArgumentException>(() => new DnsCookieService(new byte[15], clock.GetUtcNow(), null, null, clock));
        Assert.Throws<ArgumentException>(() => new DnsCookieService(new byte[16], clock.GetUtcNow().AddDays(-36), null, null, clock));
        Assert.Throws<ArgumentException>(() => new DnsCookieService(new byte[16], clock.GetUtcNow().AddMinutes(6), null, null, clock));
        Assert.Throws<ArgumentException>(() => new DnsCookieService(new byte[16], clock.GetUtcNow(), new byte[16], null, clock));
    }
}
