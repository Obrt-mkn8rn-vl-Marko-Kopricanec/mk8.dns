using System.Buffers.Binary;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class UdpBudgetApplicationTests
{
    private static readonly byte[] Peer = [192, 0, 2, 1];

    [Fact]
    public async Task RandomQuestionsAndErrorKindsShareTheSamePrefixBudget()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, responseBurst: 2, responsesPerSecond: 1);
        var application = Create(limiter);
        Assert.NotEmpty(await application.ExchangeAsync(AuthorityFixture.Query(), false, Peer, CancellationToken.None).ConfigureAwait(true));
        Assert.NotEmpty(await application.ExchangeAsync(AuthorityFixture.Query("missing.example."), false, Peer, CancellationToken.None).ConfigureAwait(true));
        foreach (var query in new[] { AuthorityFixture.Query("fresh.example."), new byte[12], AuthorityFixture.Query(flags: 0x0900) })
            Assert.Empty(await application.ExchangeAsync(query, false, Peer, CancellationToken.None).ConfigureAwait(true));
        Assert.NotEmpty(await application.ExchangeAsync(AuthorityFixture.Query(), true, Peer, CancellationToken.None).ConfigureAwait(true));
        clock.Advance(TimeSpan.FromSeconds(1)); Assert.NotEmpty(await application.ExchangeAsync(AuthorityFixture.Query(), false, Peer, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal((3L, 3L, 1), limiter.Statistics);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task AllMalformedAndUnsupportedRepliesAreBudgeted(int kind)
    {
        var limiter = new RejectingBudget(); var application = Create(limiter);
        var query = kind switch { 0 => new byte[12], 1 => AuthorityFixture.Query(version: 1, edns: 1232), 2 => AuthorityFixture.Query(flags: 0x0900), _ => CookiePackets.Query(new byte[7]) };
        Assert.Empty(await application.ExchangeAsync(query, false, Peer, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(1, limiter.Calls); Assert.InRange(limiter.Bytes, 12, 512); Assert.Equal(Peer, limiter.Peer);
    }

    [Fact]
    public async Task ValidCookiesBypassAnExhaustedBudgetButClientOnlyAndInvalidCookiesDoNot()
    {
        var clock = new CookieClock(1559731985); using var cookies = new DnsCookieService(new byte[16], clock.GetUtcNow(), null, null, clock);
        var limiter = new RejectingBudget(); var application = Create(limiter, cookies);
        var cookie = cookies.Create(new byte[8], Peer)!;
        var response = await application.ExchangeAsync(CookiePackets.Query(cookie, type: 1), false, Peer, CancellationToken.None).ConfigureAwait(true);
        Assert.NotEmpty(response); Assert.Equal(0, limiter.Calls); Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)));
        Assert.Empty(await application.ExchangeAsync(CookiePackets.Query(new byte[8], type: 1), false, Peer, CancellationToken.None).ConfigureAwait(true));
        cookie[^1] ^= 1;
        Assert.Empty(await application.ExchangeAsync(CookiePackets.Query(cookie, type: 1), false, Peer, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(2, limiter.Calls);
        Assert.NotEmpty(await application.ExchangeAsync(CookiePackets.Query(cookie, type: 1), true, Peer, CancellationToken.None).ConfigureAwait(true)); Assert.Equal(2, limiter.Calls);
    }

    [Fact]
    public async Task ValidPeerScopedTsigKeepsItsMacAndOriginRefusals()
    {
        using var key = new TsigKey(DnsName.Parse("query-key."), TsigPackets.Secret, [DnsName.Parse("example.")], [Peer]);
        using var tsig = new TsigService([key], new CookieClock(1559731985)); var limiter = new RejectingBudget(); var application = Create(limiter, tsig: tsig);
        foreach (var owner in new[] { "www.example.", "other." })
        {
            var request = TsigPackets.Sign(AuthorityFixture.Query(owner));
            var reply = TsigPackets.Parse(await application.ExchangeAsync(request, false, Peer, CancellationToken.None).ConfigureAwait(true));
            Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac);
            Assert.Equal(string.Equals(owner, "other.", StringComparison.Ordinal) ? 5 : 0, reply.Message[3] & 15);
        }
        Assert.Equal(0, limiter.Calls);
    }

    [Theory]
    [InlineData("bad-mac")]
    [InlineData("bad-time")]
    [InlineData("bad-key")]
    [InlineData("bad-peer")]
    [InlineData("malformed")]
    public async Task FailedTsigCannotBypassAndFinalSignatureBytesAreCharged(string failure)
    {
        using var key = new TsigKey(DnsName.Parse("query-key."), TsigPackets.Secret, [DnsName.Parse("example.")], [Peer]);
        using var tsig = new TsigService([key], new CookieClock(1559731985)); var budget = new RejectingBudget();
        var request = TsigPackets.Sign(AuthorityFixture.Query(), time: string.Equals(failure, "bad-time", StringComparison.Ordinal) ? 1UL : 1559731985UL,
            key: string.Equals(failure, "bad-key", StringComparison.Ordinal) ? "unknown-key." : "query-key.");
        if (string.Equals(failure, "bad-mac", StringComparison.Ordinal)) request[^7] ^= 1;
        if (string.Equals(failure, "malformed", StringComparison.Ordinal)) request = request[..^1];
        var peer = string.Equals(failure, "bad-peer", StringComparison.Ordinal) ? new byte[] { 192, 0, 2, 2 } : Peer;
        var baseline = await Create(null, tsig: tsig).ExchangeAsync(request, false, peer, CancellationToken.None).ConfigureAwait(true);
        Assert.Empty(await Create(budget, tsig: tsig).ExchangeAsync(request, false, peer, CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(1, budget.Calls); Assert.Equal(baseline.Length, budget.Bytes); Assert.Equal(peer, budget.Peer);
        Assert.NotEmpty(await Create(budget, tsig: tsig).ExchangeAsync(request, true, peer, CancellationToken.None).ConfigureAwait(true)); Assert.Equal(1, budget.Calls);
    }

    [Fact]
    public async Task EmptyUnanswerablePacketsDoNotConsumeBudgetState()
    {
        var budget = new RejectingBudget(); Assert.Empty(await Create(budget).ExchangeAsync(new byte[2], false, Peer, CancellationToken.None).ConfigureAwait(true)); Assert.Equal(0, budget.Calls);
    }

    private static AuthoritativeApplication Create(IDnsResponseLimiter? budget, DnsCookieService? cookies = null, TsigService? tsig = null) =>
        new(new AuthoritativeCatalog([AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 42]))]), new DnsMessageCodecAdapter(), "budget", cookies, tsig, budget);

    private sealed class RejectingBudget : IDnsResponseLimiter
    {
        internal int Calls { get; private set; }
        internal int Bytes { get; private set; }
        internal byte[] Peer { get; private set; } = [];
        public bool TryAdmit(ReadOnlySpan<byte> peerAddress, int responseBytes)
        {
            Calls++; Bytes = responseBytes; Peer = peerAddress.ToArray(); return false;
        }
    }
}
