using System.Buffers.Binary;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TsigAdmissionTests
{
    [Theory]
    [InlineData("class")]
    [InlineData("ttl")]
    [InlineData("algorithm-compression")]
    [InlineData("request-error")]
    [InlineData("other-length")]
    [InlineData("not-last")]
    [InlineData("duplicate")]
    [InlineData("answer-section")]
    [InlineData("authority-section")]
    public async Task MalformedSignaturePlacementAndMetadataFailClosed(string corruption)
    {
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var request = TsigPackets.Sign(AuthorityFixture.Query());
        var parsed = TsigPackets.Parse(request);
        var type = parsed.RecordOffset + DnsName.Parse("query-key.").ToWire().Length;
        switch (corruption)
        {
            case "class": request[type + 3] = 1; break;
            case "ttl": request[type + 7] = 1; break;
            case "algorithm-compression": request[type + 10] = 0xc0; request[type + 11] = 0x0c; break;
            case "request-error": request[^3] = 1; break;
            case "other-length": request[^1] = 1; break;
            case "not-last": request = [.. request, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]; BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(10), 2); break;
            case "duplicate": request = [.. request, .. request[parsed.RecordOffset..]]; BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(10), 2); break;
            case "answer-section": BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(6), 1); BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(10), 0); break;
            case "authority-section": BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(8), 1); BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(10), 0); break;
        }
        var reply = await Create(tsig).ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(12, reply.Length); Assert.Equal(1, reply[3] & 15); Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(10)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(15)]
    [InlineData(33)]
    public async Task AlgorithmImpossibleMacLengthsProduceFormerr(int size)
    {
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var request = TsigPackets.Append(AuthorityFixture.Query(), "query-key.", "hmac-sha256.", 1559731985, 300, new byte[size], 0xabcd, 0, []);
        var response = await Create(tsig).ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(12, response.Length); Assert.Equal(1, response[3] & 15);
    }

    [Fact]
    public async Task EveryTruncatedSignatureIsRejectedAndDoesNotPoisonTheNextQuery()
    {
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var application = Create(tsig);
        var request = TsigPackets.Sign(AuthorityFixture.Query());
        for (var length = 12; length < request.Length; length++)
        {
            var response = await application.ExchangeAsync(request.AsMemory(0, length), false, new byte[4], CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(12, response.Length); Assert.Equal(1, response[3] & 15);
        }
        var good = TsigPackets.Parse(await application.ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(0, good.Error); Assert.Equal(TsigPackets.ExpectedMac(good, request), good.Mac);
    }

    [Fact]
    public async Task AuthenticatedDnsFormatAndUnsupportedOpcodeErrorsRemainSigned()
    {
        using var key = Key(); using var tsig = new TsigService([key], new CookieClock(1559731985));
        var application = Create(tsig);
        var plain = AuthorityFixture.Query();
        plain = [.. plain, .. plain[12..]]; BinaryPrimitives.WriteUInt16BigEndian(plain.AsSpan(4), 2);
        var malformed = TsigPackets.Sign(plain);
        var first = await application.ExchangeAsync(malformed, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, first[3] & 15); Assert.Equal(TsigPackets.ExpectedMac(TsigPackets.Parse(first), malformed), TsigPackets.Parse(first).Mac);
        var opcode = TsigPackets.Sign(AuthorityFixture.Query(flags: 0x2100));
        var unsupported = await application.ExchangeAsync(opcode, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(4, unsupported[3] & 15); Assert.Equal(TsigPackets.ExpectedMac(TsigPackets.Parse(unsupported), opcode), TsigPackets.Parse(unsupported).Mac);
    }

    [Fact]
    public async Task LongUnknownIdentifiersCannotOverrunConservativeUdpErrors()
    {
        using var tsig = new TsigService([], new CookieClock(1559731985));
        var longName = string.Join('.', new string('a', 63), new string('b', 63), new string('c', 63), new string('d', 61)) + ".";
        var request = TsigPackets.Sign(AuthorityFixture.Query(), key: longName, algorithm: longName);
        var application = Create(tsig);
        var udp = await application.ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Empty(udp);
        var tcp = TsigPackets.Parse(await application.ExchangeAsync(request, true, new byte[4], CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(17, tcp.Error); Assert.Empty(tcp.Mac);
    }

    [Fact]
    public async Task ParentSideDsUsesTheParentKeyScopeAndChildDataUsesTheChildScope()
    {
        var parent = AuthorityFixture.Zone(AuthorityFixture.Record("child.example.", 2, DnsName.Parse("ns.child.example.").ToWire()), AuthorityFixture.Record("child.example.", 43, AuthorityFixture.DsData(1)));
        var child = AuthorityFixture.ZoneAt("child.example.");
        using var childKey = new TsigKey(DnsName.Parse("query-key."), TsigPackets.Secret, [child.Origin], [new byte[4]]);
        using var tsig = new TsigService([childKey], new CookieClock(1559731985));
        var application = new AuthoritativeApplication(new AuthoritativeCatalog([parent, child]), new DnsMessageCodecAdapter(), "tsig", null, tsig);
        var request = TsigPackets.Sign(AuthorityFixture.Query("child.example.", 43));
        var refused = await application.ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(5, refused[3] & 15); Assert.Equal(TsigPackets.ExpectedMac(TsigPackets.Parse(refused), request), TsigPackets.Parse(refused).Mac);
        var soa = TsigPackets.Sign(AuthorityFixture.Query("child.example.", 6));
        var accepted = await application.ExchangeAsync(soa, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, accepted[3] & 15); Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(accepted.AsSpan(6)));
    }

    [Fact]
    public async Task ZeroQuestionCookiePrefetchIsAuthenticatedWithoutZoneData()
    {
        var clock = new CookieClock(1559731985);
        using var key = Key(); using var tsig = new TsigService([key], clock); using var cookies = DnsCookieService.CreateEphemeral(clock);
        var application = new AuthoritativeApplication(new AuthoritativeCatalog([AuthorityFixture.Zone()]), new DnsMessageCodecAdapter(), "tsig", cookies, tsig);
        var request = TsigPackets.Sign(CookiePackets.Query(new byte[8], prefetch: true));
        var response = await application.ExchangeAsync(request, false, new byte[4], CancellationToken.None).ConfigureAwait(true);
        var reply = TsigPackets.Parse(response);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(4))); Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)));
        Assert.Equal(0, reply.Error); Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac); Assert.Equal(24, CookiePackets.ResponseCookie(reply.Message).Length);
    }

    private static TsigKey Key() => new(DnsName.Parse("query-key."), TsigPackets.Secret, [DnsName.Parse("example.")], [new byte[4]]);
    private static AuthoritativeApplication Create(TsigService tsig) => new(new AuthoritativeCatalog([AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 42]))]), new DnsMessageCodecAdapter(), "tsig", null, tsig);
}
