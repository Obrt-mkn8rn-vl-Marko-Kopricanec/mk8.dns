using System.Buffers.Binary;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TsigApplicationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RepliesBindTheRequestMacAndExactDnsBytes(bool tcp)
    {
        var clock = new CookieClock(1559731985);
        using var key = Key(); using var tsig = new TsigService([key], clock);
        var application = Create(tsig);
        var request = TsigPackets.Sign(AuthorityFixture.Query());
        var response = await application.ExchangeAsync(request, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var reply = TsigPackets.Parse(response);
        Assert.Equal(0, reply.Error); Assert.Equal(32, reply.Mac.Length); Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)));
        Assert.Equal(new byte[] { 192, 0, 2, 42 }, reply.Message[^4..]);
        Assert.Equal((byte)0x85, response[2]);
        var plain = await application.ExchangeAsync(AuthorityFixture.Query(), tcp, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(plain.AsSpan(10)));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(20)]
    [InlineData(31)]
    [InlineData(32)]
    public async Task PermittedTruncationUsesTheTransmittedRequestMac(int length)
    {
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var request = TsigPackets.Sign(AuthorityFixture.Query(), macLength: length);
        var response = await Create(tsig).ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var reply = TsigPackets.Parse(response);
        Assert.Equal(0, reply.Error); Assert.Equal(32, reply.Mac.Length); Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac);
    }

    [Theory]
    [InlineData(-301, 18)]
    [InlineData(-300, 0)]
    [InlineData(0, 0)]
    [InlineData(300, 0)]
    [InlineData(301, 18)]
    [InlineData(3600, 18)]
    public async Task TimeWindowAndBadtimeUseClientTimeAndAuthenticatedServerTime(int delta, int error)
    {
        const ulong now = 1559731985;
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock((long)now));
        var time = (ulong)((long)now + delta);
        var request = TsigPackets.Sign(AuthorityFixture.Query(), time: time);
        var response = await Create(tsig).ExchangeAsync(request, true, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var reply = TsigPackets.Parse(response);
        Assert.Equal(error, reply.Error); Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac);
        Assert.Equal(error == 18 ? time : now, reply.Time);
        if (error == 18)
        {
            Assert.Equal(9, response[3] & 15); Assert.Equal(new byte[] { 0, 0, 0x5c, 0xf7, 0x9f, 0x11 }, reply.Other); Assert.Equal(300, reply.Fudge);
        }
        else Assert.Empty(reply.Other);
    }

    [Fact]
    public async Task AuthenticationTimeAndLocalTruncationPolicyAreCheckedInOrder()
    {
        using var key = Key(minimum: 32); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var application = Create(tsig);
        var truncated = TsigPackets.Sign(AuthorityFixture.Query(), macLength: 16);
        var rejected = TsigPackets.Parse(await application.ExchangeAsync(truncated, false, new byte[4], CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(22, rejected.Error); Assert.Equal(TsigPackets.ExpectedMac(rejected, truncated), rejected.Mac);
        var stale = TsigPackets.Sign(AuthorityFixture.Query(), time: 1, macLength: 16);
        var time = TsigPackets.Parse(await application.ExchangeAsync(stale, false, new byte[4], CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(18, time.Error); Assert.Equal(TsigPackets.ExpectedMac(time, stale), time.Mac);
        stale[^7] ^= 1;
        var bad = TsigPackets.Parse(await application.ExchangeAsync(stale, false, new byte[4], CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(16, bad.Error); Assert.Empty(bad.Mac); Assert.Empty(bad.Other);
    }

    [Theory]
    [InlineData("unknown-key.", "hmac-sha256.")]
    [InlineData("query-key.", "hmac-sha1.")]
    public async Task UnknownKeyOrUnagreedAlgorithmHasAnUnsignedBadkey(string name, string algorithm)
    {
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var request = TsigPackets.Sign(AuthorityFixture.Query(), key: name, algorithm: algorithm);
        var response = await Create(tsig).ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var reply = TsigPackets.Parse(response);
        Assert.Equal(9, response[3] & 15); Assert.Equal(17, reply.Error); Assert.Empty(reply.Mac);
    }

    [Fact]
    public async Task IdRewritingAndCanonicalKeyNamesAreAuthenticatedCorrectly()
    {
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var request = TsigPackets.Sign(AuthorityFixture.Query("WWW.Example."), key: "QuErY-KeY.", algorithm: "HMAC-SHA256.", other: [1, 2, 3]);
        request[0] = 0x12; request[1] = 0x34;
        var response = await Create(tsig).ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var reply = TsigPackets.Parse(response);
        Assert.Equal(0, reply.Error); Assert.Equal((ushort)0xabcd, reply.Id); Assert.Equal((ushort)0x1234, BinaryPrimitives.ReadUInt16BigEndian(response));
        Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac); Assert.Equal("query-key.", reply.Key); Assert.Equal("hmac-sha256.", reply.Algorithm);
        Assert.Equal(AuthorityFixture.Query("WWW.Example.")[12..], reply.Message.AsSpan(12, 17).ToArray());
    }

    [Fact]
    public async Task ExactPeerAndServedZoneScopesDenyAuthenticatedQueriesWithSignedRefused()
    {
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var application = Create(tsig, zones: [AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 42])), AuthorityFixture.ZoneAt("child.example.")]);
        foreach (var request in new[] { TsigPackets.Sign(AuthorityFixture.Query("child.example.")), TsigPackets.Sign(AuthorityFixture.Query("outside.")) })
        {
            var response = await application.ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
            var reply = TsigPackets.Parse(response);
            Assert.Equal(5, response[3] & 15); Assert.Equal(0, reply.Error); Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac);
        }
        var denied = TsigPackets.Sign(AuthorityFixture.Query());
        var peerResponse = await application.ExchangeAsync(denied, false, new byte[16], CancellationToken.None).ConfigureAwait(true);
        var peerReply = TsigPackets.Parse(peerResponse);
        Assert.Equal(5, peerResponse[3] & 15); Assert.Equal(TsigPackets.ExpectedMac(peerReply, denied), peerReply.Mac);
    }

    [Fact]
    public async Task SignatureReservationAndCookieChallengeRetryProduceSignedTcpFallback()
    {
        var clock = new CookieClock(1559731985);
        using var key = Key(); using var tsig = new TsigService([key], clock); using var cookies = DnsCookieService.CreateEphemeral(clock);
        var application = Create(tsig, cookies, [AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 65280, new byte[450]))]);
        var unverified = TsigPackets.Sign(AuthorityFixture.Query(type: 65280, edns: 1232));
        var limited = await application.ExchangeAsync(unverified, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var truncation = TsigPackets.Parse(limited);
        Assert.True((limited[2] & 2) != 0); Assert.Equal(0, limited[3] & 15); Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(limited.AsSpan(6)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(limited.AsSpan(10))); Assert.Equal(TsigPackets.ExpectedMac(truncation, unverified), truncation.Mac); Assert.InRange(limited.Length, 1, 512);
        var hello = TsigPackets.Sign(CookiePackets.Query(new byte[8], type: 65280));
        var challenge = await application.ExchangeAsync(hello, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var signedChallenge = TsigPackets.Parse(challenge);
        Assert.Equal(23, CookiePackets.ResponseCode(signedChallenge.Message)); Assert.Equal(TsigPackets.ExpectedMac(signedChallenge, hello), signedChallenge.Mac);
        var learned = CookiePackets.ResponseCookie(signedChallenge.Message);
        var retry = TsigPackets.Sign(CookiePackets.Query(learned, type: 65280));
        var full = await application.ExchangeAsync(retry, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var reply = TsigPackets.Parse(full); Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(full.AsSpan(6))); Assert.Equal(TsigPackets.ExpectedMac(reply, retry), reply.Mac); Assert.InRange(full.Length, 513, 1232);
        var tcp = await application.ExchangeAsync(unverified, true, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(tcp.AsSpan(6))); Assert.Equal(TsigPackets.ExpectedMac(TsigPackets.Parse(tcp), unverified), TsigPackets.Parse(tcp).Mac);
    }

    [Fact]
    public async Task ValidRequestsReceiveSignedServfailAfterCookiePolicyExpiry()
    {
        var clock = new CookieClock(1559731985);
        using var key = Key(); using var tsig = new TsigService([key], clock); using var cookies = new DnsCookieService(new byte[16], clock.GetUtcNow(), null, null, clock);
        var application = Create(tsig, cookies); clock.Advance(36 * 86400);
        var request = TsigPackets.Sign(AuthorityFixture.Query(), time: (ulong)clock.GetUtcNow().ToUnixTimeSeconds());
        var response = await application.ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var reply = TsigPackets.Parse(response); Assert.Equal(2, response[3] & 15); Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac);
        Assert.False((await application.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
    }

    private static TsigKey Key(byte minimum = 16) => new(DnsName.Parse("query-key."), TsigPackets.Secret, [DnsName.Parse("example.")], [new byte[4]], minimum);
    private static AuthoritativeApplication Create(TsigService tsig, DnsCookieService? cookies = null, AuthoritativeZone[]? zones = null) => new(new AuthoritativeCatalog(zones ?? [AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 42]))]), new DnsMessageCodecAdapter(), "tsig", cookies, tsig);
}
