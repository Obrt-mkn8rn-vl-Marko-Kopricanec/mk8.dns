using System.Buffers.Binary;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TsigZoneScopeTests
{
    [Theory]
    [InlineData("cname", false, false)]
    [InlineData("cname", true, false)]
    [InlineData("dname", false, false)]
    [InlineData("dname", true, false)]
    [InlineData("cname", false, true)]
    [InlineData("cname", true, true)]
    [InlineData("dname", false, true)]
    [InlineData("dname", true, true)]
    public async Task CrossZoneAliasesRequireEverySelectedOrigin(string alias, bool tcp, bool both)
    {
        var first = AliasZone(alias, "other.");
        var second = AuthorityFixture.ZoneAt("other.", AuthorityFixture.Record("target.other.", 1, [192, 0, 2, 43]));
        using var key = Key(both ? [first.Origin, second.Origin] : [first.Origin]);
        using var tsig = new TsigService([key], Clock());
        var application = Application([first, second], tsig);
        var plain = AuthorityFixture.Query(Owner(alias));
        var signed = TsigPackets.Sign(plain);
        var reply = Verify(await application.ExchangeAsync(signed, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true), signed, both ? 0 : 5);
        if (both)
        {
            Assert.Equal(string.Equals(alias, "cname", StringComparison.Ordinal) ? 2 : 3, Count(reply, 6));
            Assert.Equal(new byte[] { 192, 0, 2, 43 }, reply.Message[^4..]);
        }
        else EmptyRefusal(reply);
        var unsigned = await application.ExchangeAsync(plain, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, unsigned[3] & 15); Assert.Equal(string.Equals(alias, "cname", StringComparison.Ordinal) ? 2 : 3, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(6)));
        var direct = TsigPackets.Sign(AuthorityFixture.Query("target.other."));
        Verify(await application.ExchangeAsync(direct, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true), direct, both ? 0 : 5);
    }

    [Theory]
    [InlineData("cname", false)]
    [InlineData("cname", true)]
    [InlineData("dname", false)]
    [InlineData("dname", true)]
    public async Task SameZoneAliasesRemainSigned(string alias, bool tcp)
    {
        var zone = AliasZone(alias, "example.", AuthorityFixture.Record("target.example.", 1, [192, 0, 2, 42]));
        using var key = Key([zone.Origin]); using var tsig = new TsigService([key], Clock());
        var request = TsigPackets.Sign(AuthorityFixture.Query(Owner(alias)));
        var reply = Verify(await Application([zone], tsig).ExchangeAsync(request, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true), request, 0);
        Assert.Equal(string.Equals(alias, "cname", StringComparison.Ordinal) ? 2 : 3, Count(reply, 6)); Assert.Equal(new byte[] { 192, 0, 2, 42 }, reply.Message[^4..]);
    }

    [Theory]
    [InlineData("nxdomain", false, false)]
    [InlineData("nodata", false, false)]
    [InlineData("referral", false, false)]
    [InlineData("nxdomain", true, false)]
    [InlineData("nodata", true, false)]
    [InlineData("referral", true, false)]
    [InlineData("nxdomain", false, true)]
    [InlineData("nodata", false, true)]
    [InlineData("referral", false, true)]
    [InlineData("nxdomain", true, true)]
    [InlineData("nodata", true, true)]
    [InlineData("referral", true, true)]
    public async Task ChainedAliasesAuthorizeNegativeAndReferralProvenance(string result, bool tcp, bool all)
    {
        var first = AuthorityFixture.Zone(AuthorityFixture.Record("alias.example.", 5, DnsName.Parse("target.map.middle.").ToWire()));
        var middle = AuthorityFixture.ZoneAt("middle.", AuthorityFixture.Record("map.middle.", 39, DnsName.Parse(string.Equals(result, "referral", StringComparison.Ordinal) ? "cut.other." : "other.").ToWire()));
        var last = TerminalZone(result);
        using var key = Key(all ? [first.Origin, middle.Origin, last.Origin] : [first.Origin, middle.Origin]);
        using var tsig = new TsigService([key], Clock());
        var request = TsigPackets.Sign(AuthorityFixture.Query("alias.example."));
        var reply = Verify(await Application([first, middle, last], tsig).ExchangeAsync(request, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true), request, all ? string.Equals(result, "nxdomain", StringComparison.Ordinal) ? 3 : 0 : 5);
        if (!all) EmptyRefusal(reply);
        else
        {
            Assert.Equal(3, Count(reply, 6)); Assert.Equal(1, Count(reply, 8));
            Assert.Equal(string.Equals(result, "referral", StringComparison.Ordinal) ? 1 : 0, Count(reply, 10));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GrantingFirstAndLastDoesNotAuthorizeAnIntermediateZone(bool tcp)
    {
        var first = AuthorityFixture.Zone(AuthorityFixture.Record("alias.example.", 5, DnsName.Parse("alias.middle.").ToWire()));
        var middle = AuthorityFixture.ZoneAt("middle.", AuthorityFixture.Record("alias.middle.", 5, DnsName.Parse("target.other.").ToWire()));
        var last = AuthorityFixture.ZoneAt("other.", AuthorityFixture.Record("target.other.", 1, [192, 0, 2, 43]));
        using var key = Key([first.Origin, last.Origin]); using var tsig = new TsigService([key], Clock());
        var request = TsigPackets.Sign(AuthorityFixture.Query("alias.example."));
        EmptyRefusal(Verify(await Application([first, middle, last], tsig).ExchangeAsync(request, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true), request, 5));
    }

    [Theory]
    [InlineData("cname", 43, true)]
    [InlineData("dname", 43, true)]
    [InlineData("cname", 43, false)]
    [InlineData("dname", 43, false)]
    [InlineData("cname", 6, true)]
    [InlineData("dname", 6, true)]
    [InlineData("cname", 6, false)]
    [InlineData("dname", 6, false)]
    public async Task AliasTargetDsUsesParentProvenanceAndSoaUsesChildProvenance(string alias, int type, bool parentGrant)
    {
        var first = string.Equals(alias, "cname", StringComparison.Ordinal) ? AuthorityFixture.Zone(AuthorityFixture.Record("alias.example.", 5, DnsName.Parse("child.other.").ToWire())) : AliasZone(alias, "other.");
        var parent = AuthorityFixture.ZoneAt("other.", AuthorityFixture.Record("child.other.", 2, DnsName.Parse("ns.child.other.").ToWire()), AuthorityFixture.Record("child.other.", 43, AuthorityFixture.DsData(1)));
        var child = AuthorityFixture.ZoneAt("child.other.");
        using var key = Key([first.Origin, parentGrant ? parent.Origin : child.Origin]); using var tsig = new TsigService([key], Clock());
        var request = TsigPackets.Sign(AuthorityFixture.Query(string.Equals(alias, "cname", StringComparison.Ordinal) ? "alias.example." : "child.map.example.", (ushort)type));
        var permitted = parentGrant == (type == 43);
        var reply = Verify(await Application([first, parent, child], tsig).ExchangeAsync(request, true, new byte[4], CancellationToken.None).ConfigureAwait(true), request, permitted ? 0 : 5);
        if (permitted) Assert.Equal(string.Equals(alias, "cname", StringComparison.Ordinal) ? 2 : 3, Count(reply, 6));
        else EmptyRefusal(reply);
    }

    [Theory]
    [InlineData("cname", false, false)]
    [InlineData("dname", false, false)]
    [InlineData("cname", true, false)]
    [InlineData("dname", true, false)]
    [InlineData("cname", false, true)]
    [InlineData("dname", false, true)]
    [InlineData("cname", true, true)]
    [InlineData("dname", true, true)]
    public async Task CookieBootstrapAndRetryCannotBypassAliasGrants(string alias, bool tcp, bool both)
    {
        var first = AliasZone(alias, "other.");
        var last = AuthorityFixture.ZoneAt("other.", AuthorityFixture.Record("target.other.", 1, [192, 0, 2, 43]));
        var clock = Clock(); using var cookies = DnsCookieService.CreateEphemeral(clock);
        using var key = Key(both ? [first.Origin, last.Origin] : [first.Origin]); using var tsig = new TsigService([key], clock);
        var application = Application([first, last], tsig, cookies);
        var hello = TsigPackets.Sign(CookieQuery(Owner(alias), new byte[8]));
        var challenged = Verify(await application.ExchangeAsync(hello, false, new byte[4], CancellationToken.None).ConfigureAwait(true), hello, 7);
        Assert.Equal(23, CookiePackets.ResponseCode(challenged.Message)); Assert.Equal(0, Count(challenged, 6));
        var request = TsigPackets.Sign(CookieQuery(Owner(alias), CookiePackets.ResponseCookie(challenged.Message)));
        var reply = Verify(await application.ExchangeAsync(request, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true), request, both ? 0 : 5);
        if (both) Assert.Equal(string.Equals(alias, "cname", StringComparison.Ordinal) ? 2 : 3, Count(reply, 6));
        else EmptyRefusal(reply);
        Assert.InRange(reply.Message.Length + 82, 1, tcp ? ushort.MaxValue : 1232);
    }

    [Theory]
    [InlineData("cname")]
    [InlineData("dname")]
    public async Task UnservedAliasTargetAndExplicitAliasDataDoNotRequireAnUnselectedOrigin(string alias)
    {
        var first = AliasZone(alias, "outside.");
        using var key = Key([first.Origin]); using var tsig = new TsigService([key], Clock());
        var application = Application([first], tsig);
        foreach (var type in new ushort[] { 1, 5, 255 })
        {
            var request = TsigPackets.Sign(AuthorityFixture.Query(Owner(alias), type));
            var reply = Verify(await application.ExchangeAsync(request, true, new byte[4], CancellationToken.None).ConfigureAwait(true), request, 0);
            Assert.True(Count(reply, 6) > 0);
        }
    }

    [Fact]
    public void OriginPredicateChecksActualSelectionsAndNullIsNotAnAuthorizationMode()
    {
        var first = AliasZone("cname", "other.");
        var last = AuthorityFixture.ZoneAt("other.", AuthorityFixture.Record("target.other.", 1, [192, 0, 2, 43]));
        var catalog = new AuthoritativeCatalog([first, last]);
        var question = new DnsQuestion(DnsName.Parse("alias.example."), 1, 1);
        List<DnsName> selected = [];
        var denied = catalog.Resolve(question, origin => { selected.Add(origin); return origin.Equals(first.Origin); });
        Assert.Equal(new[] { first.Origin, last.Origin }, selected);
        Assert.Equal(5, denied.ResponseCode); Assert.Empty(denied.Answers); Assert.Empty(denied.Authority); Assert.Empty(denied.Additional);
        Assert.Throws<ArgumentNullException>(() => catalog.Resolve(question, null!));
        Assert.Equal(2, catalog.Resolve(question).Answers.Count);
    }

    [Fact]
    public async Task ReferralGlueUsesSelectedParentProvenanceEvenWhenOwnerMatchesAnotherServedZone()
    {
        var parent = AuthorityFixture.Zone(AuthorityFixture.Record("alias.example.", 5, DnsName.Parse("target.cut.example.").ToWire()),
            AuthorityFixture.Record("cut.example.", 2, DnsName.Parse("ns.child.example.").ToWire()), AuthorityFixture.Record("ns.child.example.", 1, [192, 0, 2, 42]));
        var child = AuthorityFixture.ZoneAt("child.example.", AuthorityFixture.Record("ns.child.example.", 1, [192, 0, 2, 43]));
        using var key = Key([parent.Origin]); using var tsig = new TsigService([key], Clock());
        var application = Application([parent, child], tsig);
        var request = TsigPackets.Sign(AuthorityFixture.Query("alias.example."));
        var reply = Verify(await application.ExchangeAsync(request, true, new byte[4], CancellationToken.None).ConfigureAwait(true), request, 0);
        Assert.Equal(1, Count(reply, 6)); Assert.Equal(1, Count(reply, 8)); Assert.Equal(1, Count(reply, 10)); Assert.Equal(new byte[] { 192, 0, 2, 42 }, reply.Message[^4..]);
        var direct = TsigPackets.Sign(AuthorityFixture.Query("ns.child.example."));
        EmptyRefusal(Verify(await application.ExchangeAsync(direct, true, new byte[4], CancellationToken.None).ConfigureAwait(true), direct, 5));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WildcardSynthesizedAliasesStillRequireTargetOriginGrant(bool tcp)
    {
        var first = AuthorityFixture.Zone(AuthorityFixture.Record("*.example.", 5, DnsName.Parse("target.other.").ToWire()));
        var last = AuthorityFixture.ZoneAt("other.", AuthorityFixture.Record("target.other.", 1, [192, 0, 2, 43]));
        using var key = Key([first.Origin]); using var tsig = new TsigService([key], Clock());
        var request = TsigPackets.Sign(AuthorityFixture.Query("wild.example."));
        EmptyRefusal(Verify(await Application([first, last], tsig).ExchangeAsync(request, tcp, new byte[4], CancellationToken.None).ConfigureAwait(true), request, 5));
    }

    private static AuthoritativeZone AliasZone(string alias, string target, params DnsRecord[] records) => AuthorityFixture.Zone([string.Equals(alias, "cname", StringComparison.Ordinal)
        ? AuthorityFixture.Record("alias.example.", 5, DnsName.Parse("target." + target).ToWire())
        : AuthorityFixture.Record("map.example.", 39, DnsName.Parse(target).ToWire()), .. records]);
    private static AuthoritativeZone TerminalZone(string result) => AuthorityFixture.ZoneAt("other.", result switch
    {
        "nodata" => [AuthorityFixture.Record("target.other.", 16, [1, (byte)'x'])],
        "referral" => [AuthorityFixture.Record("cut.other.", 2, DnsName.Parse("ns.cut.other.").ToWire()), AuthorityFixture.Record("ns.cut.other.", 1, [192, 0, 2, 43])],
        _ => [],
    });
    private static string Owner(string alias) => string.Equals(alias, "cname", StringComparison.Ordinal) ? "alias.example." : "target.map.example.";
    private static CookieClock Clock() => new(1559731985);
    private static TsigKey Key(DnsName[] origins) => new(DnsName.Parse("query-key."), TsigPackets.Secret, origins, [new byte[4]]);
    private static AuthoritativeApplication Application(AuthoritativeZone[] zones, TsigService tsig, DnsCookieService? cookies = null) => new(new AuthoritativeCatalog(zones), new DnsMessageCodecAdapter(), "tsig-scopes", cookies, tsig);
    private static int Count(TsigReply reply, int offset) => BinaryPrimitives.ReadUInt16BigEndian(reply.Message.AsSpan(offset));
    private static TsigReply Verify(byte[] response, byte[] request, int rcode)
    {
        var reply = TsigPackets.Parse(response);
        Assert.Equal(0, reply.Error); Assert.Equal(32, reply.Mac.Length); Assert.Equal(TsigPackets.ExpectedMac(reply, request), reply.Mac);
        Assert.Equal(rcode, response[3] & 15);
        return reply;
    }
    private static void EmptyRefusal(TsigReply reply)
    {
        Assert.Equal(5, reply.Message[3] & 15); Assert.Equal(0, reply.Message[2] & 4); Assert.Equal(0, Count(reply, 6)); Assert.Equal(0, Count(reply, 8));
        // OPT may remain; no alias, SOA, NS or glue RR can survive the denied selection.
        Assert.InRange(Count(reply, 10), 0, 1);
    }
    private static byte[] CookieQuery(string owner, byte[] cookie)
    {
        var query = AuthorityFixture.Query(owner, edns: 1232);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(query.Length - 2), (ushort)(cookie.Length + 4));
        return [.. query, 0, 10, 0, (byte)cookie.Length, .. cookie];
    }
}
