using System.Buffers.Binary;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CookieApplicationTests
{
    [Fact]
    public async Task UdpBootstrapRetryAndTcpFallbackRespectWholeRrsetsAndLimits()
    {
        var clock = new CookieClock(1559731985);
        using var cookies = DnsCookieService.CreateEphemeral(clock);
        var application = Create(cookies);
        var peer = new byte[] { 192, 0, 2, 1 };
        var small = await application.ExchangeAsync(CookiePackets.Query(null), false, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.True(small.Length <= 512);
        Assert.Equal((byte)0x87, small[2]);
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(small.AsSpan(6)));
        var hello = await application.ExchangeAsync(CookiePackets.Query(new byte[8]), false, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(23, CookiePackets.ResponseCode(hello));
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(hello.AsSpan(6)));
        var learned = CookiePackets.ResponseCookie(hello);
        Assert.True(cookies.Validate(learned, peer));
        var full = await application.ExchangeAsync(CookiePackets.Query(learned), false, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, CookiePackets.ResponseCode(full));
        Assert.InRange(full.Length, 513, 1232);
        Assert.Equal((ushort)3, BinaryPrimitives.ReadUInt16BigEndian(full.AsSpan(6)));
        var changedPeer = await application.ExchangeAsync(CookiePackets.Query(learned), false, new byte[] { 192, 0, 2, 2 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(23, CookiePackets.ResponseCode(changedPeer));
        var tcp = await application.ExchangeAsync(CookiePackets.Query(new byte[8]), true, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, CookiePackets.ResponseCode(tcp));
        Assert.Equal((ushort)3, BinaryPrimitives.ReadUInt16BigEndian(tcp.AsSpan(6)));
        var tcpInvalid = await application.ExchangeAsync(CookiePackets.Query(new byte[24]), true, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, CookiePackets.ResponseCode(tcpInvalid));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(15)]
    [InlineData(41)]
    public async Task MalformedFirstCookieCannotBeHiddenByAValidSecondCookie(int length)
    {
        using var cookies = DnsCookieService.CreateEphemeral(TimeProvider.System);
        var application = Create(cookies);
        var response = await application.ExchangeAsync(CookiePackets.Query(new byte[length], second: new byte[8]), false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(12, response.Length);
        Assert.Equal((byte)1, (byte)(response[3] & 15));
    }

    [Fact]
    public async Task FirstCookieIsUsedAndLaterCookiesAreIgnored()
    {
        using var cookies = DnsCookieService.CreateEphemeral(TimeProvider.System);
        var first = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var response = await Create(cookies).ExchangeAsync(CookiePackets.Query(first, second: new byte[2]), false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(first, CookiePackets.ResponseCookie(response)[..8]);
        Assert.Equal(23, CookiePackets.ResponseCode(response));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CookieOnlyPrefetchHasNoQuestionAndChecksInvalidServerCookies(bool tcp)
    {
        using var cookies = DnsCookieService.CreateEphemeral(TimeProvider.System);
        var application = Create(cookies);
        var peer = new byte[16];
        var first = await application.ExchangeAsync(CookiePackets.Query(new byte[8], prefetch: true), tcp, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(new byte[] { 0xab, 0xcd, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, first[..12]);
        Assert.Equal(51, first.Length);
        var cookie = CookiePackets.ResponseCookie(first);
        var valid = await application.ExchangeAsync(CookiePackets.Query(cookie, prefetch: true), tcp, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, CookiePackets.ResponseCode(valid));
        cookie[^1] ^= 1;
        var bad = await application.ExchangeAsync(CookiePackets.Query(cookie, prefetch: true), tcp, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(23, CookiePackets.ResponseCode(bad));
        var absent = await application.ExchangeAsync(CookiePackets.Query(null, prefetch: true), tcp, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal((byte)1, (byte)(absent[3] & 15));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(23)]
    [InlineData(25)]
    [InlineData(36)]
    [InlineData(40)]
    public async Task LegalButUnsupportedServerCookieFormsProduceFreshBadcookie(int length)
    {
        using var cookies = DnsCookieService.CreateEphemeral(TimeProvider.System);
        var option = new byte[length];
        option[8] = 1;
        var response = await Create(cookies).ExchangeAsync(CookiePackets.Query(option), false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(23, CookiePackets.ResponseCode(response));
        Assert.True(cookies.Validate(CookiePackets.ResponseCookie(response), new byte[4]));
    }

    [Fact]
    public async Task CookieReservationCannotOverrunSmallNegotiatedUdpAndBadversTakesPrecedence()
    {
        using var cookies = DnsCookieService.CreateEphemeral(TimeProvider.System);
        var zone = AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 65280, new byte[450]));
        var application = new AuthoritativeApplication(new AuthoritativeCatalog([zone]), new DnsMessageCodecAdapter(), "cookies", cookies);
        var cookie = cookies.Create(new byte[8], new byte[4]);
        Assert.NotNull(cookie);
        var response = await application.ExchangeAsync(CookiePackets.Query(cookie, size: 512, type: 65280), false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.InRange(response.Length, 1, 512);
        Assert.Equal((byte)0x87, response[2]);
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)));
        Assert.True(cookies.Validate(CookiePackets.ResponseCookie(response), new byte[4]));
        var badvers = await application.ExchangeAsync(CookiePackets.Query(new byte[2], version: 1), false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(new byte[] { 0, 0, 41, 4, 0xd0, 1, 0, 0, 0, 0, 0 }, badvers[^11..]);
        Assert.Equal((byte)0, (byte)(badvers[3] & 15));
    }

    [Fact]
    public async Task ExpiredStaticPolicyIsUnreadyAndReturnsServfailWithoutTouchingTheCatalog()
    {
        var clock = new CookieClock(1559731985);
        using var cookies = new DnsCookieService(new byte[16], clock.GetUtcNow(), null, null, clock);
        var application = Create(cookies);
        Assert.True((await application.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        clock.Advance(36 * 86400);
        var status = await application.GetStatusAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.False(status.DnsReady);
        Assert.Equal(1u, status.ActiveSnapshots);
        var response = await application.ExchangeAsync(CookiePackets.Query(new byte[8]), false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal((byte)2, (byte)(response[3] & 15));
        Assert.Equal(12, response.Length);
    }

    [Fact]
    public void DecodedCookieOwnershipAndResponseCorrelationAreEnforced()
    {
        var original = new byte[8];
        var query = DnsMessageCodec.DecodeQuery(CookiePackets.Query(original));
        original[0] = 99;
        var copy = query.GetCookieWire();
        Assert.NotNull(copy);
        copy[0] = 88;
        Assert.Equal(new byte[8], query.GetCookieWire());
        var wrong = new byte[24];
        wrong[0] = 1;
        Assert.Throws<ArgumentException>(() => DnsMessageCodec.EncodeResponse(query, new Mk8.Dns.Domain.DnsAnswer(0, false, [], [], []), false, wrong, 512));
    }

    private static AuthoritativeApplication Create(DnsCookieService cookies)
    {
        var records = Enumerable.Range(1, 3).Select(value => AuthorityFixture.Record("www.example.", 16, new byte[] { 250, (byte)value }.Concat(new byte[249]).ToArray()));
        return new AuthoritativeApplication(new AuthoritativeCatalog([AuthorityFixture.Zone(records.ToArray())]), new DnsMessageCodecAdapter(), "cookies", cookies);
    }
}
