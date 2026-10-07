using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SvcbMasterFileTests
{
    internal const string Header = "$ORIGIN example.\n$TTL 300\n@ SOA ns hostmaster 1 3600 600 86400 30\n  NS ns\n";
    private static readonly DnsName Origin = DnsName.Parse("example.");

    // Independent RFC 9460 Appendix D RDATA vectors and locally specified binary oracles.
    [Theory]
    [InlineData("HTTPS 0 foo.example.com.", "000003666f6f076578616d706c6503636f6d00")]
    [InlineData("SVCB 1 .", "000100")]
    [InlineData("SVCB 16 foo.example.com. port=53", "001003666f6f076578616d706c6503636f6d00000300020035")]
    [InlineData("SVCB 1 foo.example.com. key667=hello", "000103666f6f076578616d706c6503636f6d00029b000568656c6c6f")]
    [InlineData("SVCB 1 foo.example.com. key667=\"hello\\210qoo\"", "000103666f6f076578616d706c6503636f6d00029b000968656c6c6fd2716f6f")]
    [InlineData("SVCB 1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\"", "000103666f6f076578616d706c6503636f6d000006002020010db800000000000000000000000120010db8000000000000000000530001")]
    [InlineData("SVCB 1 example.com. ipv6hint=\"2001:db8:122:344::192.0.2.33\"", "0001076578616d706c6503636f6d000006001020010db80122034400000000c0000221")]
    [InlineData("SVCB 16 foo.example.org. ( alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1 )", "001003666f6f076578616d706c65036f7267000000000400010004000100090268320568332d313900040004c0000201")]
    [InlineData("SVCB 16 foo.example.org. alpn=\"f\\\\\\\\oo\\\\,bar,h2\"", "001003666f6f076578616d706c65036f7267000001000c08665c6f6f2c626172026832")]
    [InlineData("SVCB 16 foo.example.org. alpn=f\\\\\\092oo\\092,bar,h2", "001003666f6f076578616d706c65036f7267000001000c08665c6f6f2c626172026832")]
    [InlineData("HTTPS 65535 . port=\"65535\" no-default-alpn=\"\" alpn=h3", "ffff00000100030268330002000000030002ffff")]
    [InlineData("HTTPS 1 . key3=\\000\\053", "000100000300020035")]
    [InlineData("HTTPS 1 . key1=\\002h2", "00010000010003026832")]
    [InlineData("HTTPS 1 . mandatory=key1 alpn=h2", "00010000000002000100010003026832")]
    [InlineData("HTTPS 1 . key0=\\000\\001 alpn=h2", "00010000000002000100010003026832")]
    [InlineData("HTTPS 1 . ipv4hint=192.0.2.1,198.51.100.2", "00010000040008c0000201c6336402")]
    [InlineData("HTTPS 1 . key65280", "000100ff000000")]
    [InlineData("HTTPS 1 . key65280=", "000100ff000000")]
    [InlineData("HTTPS 1 . key65280=\"\"", "000100ff000000")]
    [InlineData("HTTPS 1 . key65280=\"a;b(c) d=\\\"\\000\\255\"", "000100ff00000c613b6228632920643d2200ff")]
    [InlineData("SVCB 1 . alpn=\\000\\255", "000100000100030200ff")]
    [InlineData("HTTPS 1 . alpn=h2 no-default-alpn", "0001000001000302683200020000")]
    [InlineData("HTTPS 1 . alpn=h2 no-default-alpn=", "0001000001000302683200020000")]
    public void PresentationMatchesIndependentWireAndGenericRoundTrip(string input, string hex)
    {
        var zone = Parse(input);
        var record = Assert.Single(zone.GetRecords(DnsName.Parse("svc.example.")));
        Assert.Equal(Convert.FromHexString(hex), record.GetData());
        var exported = ZoneMasterFileCodec.Export(zone);
        var restored = ZoneMasterFileCodec.Import(Origin, exported);
        Assert.Equal(ZoneBundleCodec.Compile(Guid.NewGuid(), 1, zone).GetPayload(), ZoneBundleCodec.Compile(Guid.NewGuid(), 1, restored).GetPayload());
    }

    [Theory]
    [InlineData("HTTPS 1 .", "HTTPS 1 .")]
    [InlineData("HTTPS 1 . port=443 alpn=h2,h3", "HTTPS 1 . alpn=\"h2,h3\" port=\"443\"")]
    [InlineData("HTTPS 1 . alpn=h2 mandatory=key3,alpn port=443", "HTTPS 1 . key3=\\001\\187 mandatory=alpn,port key1=\\002h2")]
    [InlineData("HTTPS 1 . key65280=\\000\\255", "HTTPS 1 . key65280=\"\\000\\255\"")]
    public void ReorderedQuotedAndRawKeysHaveSameCanonicalIntent(string first, string second)
    {
        Assert.Equal(ZoneBundleCodec.Compile(Guid.NewGuid(), 1, Parse(first)).ContentHash, ZoneBundleCodec.Compile(Guid.NewGuid(), 1, Parse(second)).ContentHash);
    }

    [Theory]
    [InlineData("SVCB -1 .")]
    [InlineData("SVCB 65536 .")]
    [InlineData("SVCB \"1\" .")]
    [InlineData("SVCB 1")]
    [InlineData("SVCB 0 .")]
    [InlineData("SVCB 0 target alpn=h2")]
    [InlineData("SVCB 1 . alpn=h2 alpn=h3")]
    [InlineData("SVCB 1 . alpn=h2 key1=\\002h3")]
    [InlineData("SVCB 1 . key123=abc key123=def")]
    [InlineData("SVCB 1 . mandatory")]
    [InlineData("SVCB 1 . alpn")]
    [InlineData("SVCB 1 . port")]
    [InlineData("SVCB 1 . ipv4hint")]
    [InlineData("SVCB 1 . ipv6hint")]
    [InlineData("SVCB 1 . no-default-alpn=abc alpn=h2")]
    [InlineData("SVCB 1 . no-default-alpn")]
    [InlineData("SVCB 1 . mandatory=mandatory")]
    [InlineData("SVCB 1 . mandatory=key0")]
    [InlineData("SVCB 1 . mandatory=alpn")]
    [InlineData("SVCB 1 . mandatory=alpn,key1 alpn=h2")]
    [InlineData("SVCB 1 . mandatory=alpn, alpn=h2")]
    [InlineData("SVCB 1 . alpn=\"\"")]
    [InlineData("SVCB 1 . alpn=,h2")]
    [InlineData("SVCB 1 . alpn=h2,")]
    [InlineData("SVCB 1 . alpn=h2,,h3")]
    [InlineData("SVCB 1 . alpn=\\092x")]
    [InlineData("SVCB 1 . alpn=h2\\092")]
    [InlineData("SVCB 1 . port=65536")]
    [InlineData("SVCB 1 . port=-1")]
    [InlineData("SVCB 1 . port=+443")]
    [InlineData("SVCB 1 . port=\"4 43\"")]
    [InlineData("SVCB 1 . port=\\000443")]
    [InlineData("SVCB 1 . ipv4hint=127.1")]
    [InlineData("SVCB 1 . ipv4hint=256.0.0.1")]
    [InlineData("SVCB 1 . ipv4hint=2001:db8::1")]
    [InlineData("SVCB 1 . ipv4hint=192.0.2.1,")]
    [InlineData("SVCB 1 . ipv6hint=192.0.2.1")]
    [InlineData("SVCB 1 . ipv6hint=fe80::1%2")]
    [InlineData("SVCB 1 . ipv6hint=::1,")]
    [InlineData("SVCB 1 . ipv6hint=::g")]
    [InlineData("SVCB 1 . ipv6hint=\" ::1\"")]
    [InlineData("SVCB 1 . ipv6hint=\\091::1\\093")]
    [InlineData("SVCB 1 . mandatory=\\000alpn alpn=h2")]
    [InlineData("SVCB 1 . ech")]
    [InlineData("SVCB 1 . ech=AA")]
    [InlineData("SVCB 1 . ech=AB==")]
    [InlineData("SVCB 1 . ech=\"AA== \"")]
    [InlineData("SVCB 1 . ech=\\255")]
    [InlineData("SVCB 1 . key01=\\002h2")]
    [InlineData("SVCB 1 . key65535")]
    [InlineData("SVCB 1 . key65536")]
    [InlineData("SVCB 1 . Key123=abc")]
    [InlineData("SVCB 1 . ALPN=h2")]
    [InlineData("SVCB 1 . unsupported=abc")]
    [InlineData("SVCB 1 . key=abc")]
    [InlineData("SVCB 1 . =abc")]
    [InlineData("SVCB 1 . key123=\\999")]
    [InlineData("SVCB 1 . key123=\\12")]
    [InlineData("SVCB 1 . key123=\"unterminated")]
    [InlineData("SVCB 1 . key123=\"abc\"joined")]
    [InlineData("SVCB 1 . \"alpn=h2\"")]
    [InlineData("SVCB 1 . key1=abc")]
    [InlineData("SVCB 1 . key3=443")]
    public void InvalidTypedOrRawParametersFailSharedAdmission(string input) => Assert.Throws<FormatException>(() => Parse(input));

    [Theory]
    [InlineData("mandatory=\\097lpn alpn=h2", "00010000000002000100010003026832")]
    [InlineData("port=\\05243", "0001000003000201bb")]
    [InlineData("ipv4hint=\\04992.0.2.1", "00010000040004c0000201")]
    [InlineData("ech=\\065A==", "0001000005000100")]
    [InlineData("ipv6hint=\\058\\0581", "0001000006001000000000000000000000000000000001")]
    [InlineData("mandatory=alpn\\044port alpn=h2 port=443", "0001000000000400010003000100030268320003000201bb")]
    [InlineData("ipv4hint=192.0.2.1\\044198.51.100.2", "00010000040008c0000201c6336402")]
    public void EveryTypedValueDecodesCharacterStringBeforeItsWireFormat(string parameters, string hex)
    {
        var record = Assert.Single(Parse("HTTPS 1 . " + parameters).GetRecords(DnsName.Parse("svc.example.")));
        Assert.Equal(Convert.FromHexString(hex), record.GetData());
    }

    [Theory]
    [InlineData("[::1]")]
    [InlineData("[::1]:443")]
    [InlineData("[::1]:0x1bb")]
    public void BracketedEndpointIsNotAnIpv6Hint(string hint) => Assert.Throws<FormatException>(() => Parse("HTTPS 1 . ipv6hint=\"" + hint + "\""));

    [Theory]
    [InlineData("key123=a=\"b\"")]
    [InlineData("key123==\"abc\"")]
    [InlineData("alpn=h2=\"h3\"")]
    public void QuotedValueCannotFollowAnUnquotedValue(string parameter) => Assert.Throws<FormatException>(() => Parse("HTTPS 1 . " + parameter));

    [Theory]
    [InlineData("host=\"label\" TXT value")]
    [InlineData("svc A host=\"192.0.2.1\"")]
    [InlineData("svc TXT key=\"value\"")]
    [InlineData("svc MX 10 target=\"name\"")]
    [InlineData("svc key=\"SVCB\" 1 .")]
    [InlineData("$ORIGIN key=\"sub\"")]
    [InlineData("svc SVCB 1 key=\"target\"")]
    public void QuotedParameterSuffixDoesNotChangeOtherFieldGrammar(string line) => Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, Header + line));

    [Fact]
    public void ValueAndRdataBoundsAreCompleteOrFail()
    {
        _ = Parse("SVCB 1 . alpn=" + new string('a', 255));
        Assert.Throws<FormatException>(() => Parse("SVCB 1 . alpn=" + new string('a', 256)));
        var record = Assert.Single(Parse("SVCB 1 . key65280=" + new string('a', 65_528)).GetRecords(DnsName.Parse("svc.example.")));
        Assert.Equal(ushort.MaxValue, record.GetData().Length);
        Assert.Throws<FormatException>(() => Parse("SVCB 1 . key65280=" + new string('a', 65_529)));
        Assert.Throws<FormatException>(() => Parse("SVCB 1 . alpn=\"h2\r\nh3\""));
    }

    [Fact]
    public void TargetNamesUseCurrentOriginAndOnlyNameCaseCanonicalizes()
    {
        var zone = ZoneMasterFileCodec.Import(Origin, Header + "$ORIGIN Sub\nsvc SVCB 1 TaRgEt key65280=MiXeD\n");
        var record = Assert.Single(zone.GetRecords(DnsName.Parse("svc.sub.example.")));
        Assert.Equal(Convert.FromHexString("00010654615267457403537562076578616d706c6500ff0000054d69586544"), record.GetData());
        Assert.Equal(Convert.FromHexString("00010674617267657403737562076578616d706c6500ff0000054d69586544"), record.GetCanonicalData());
    }

    [Fact]
    public void EchUsesPublicRfc9848ConfigurationBytesWithoutTlsKeyOwnership()
    {
        const string text = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA=";
        const string hex = "0001000005004a0048fe0d004401002000201d77eb1c522d08605b179d4214ee4a3635df7e17c336ea9006655a73fcaad63e00040001000164156563682d73697465732e6578616d706c652e6e65740000";
        var record = Assert.Single(Parse("HTTPS 1 . ech=\"" + text + "\"").GetRecords(DnsName.Parse("svc.example.")));
        Assert.Equal(Convert.FromHexString(hex), record.GetData());
    }

    private static AuthoritativeZone Parse(string input) => ZoneMasterFileCodec.Import(Origin, Header + "svc " + input + "\n");
}
