using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class MasterFileTests
{
    private const string Header = "$ORIGIN example.\n$TTL 300\n@ IN SOA ns hostmaster ( 999 1h 15m 1w 60 )\n  IN NS ns\n";
    private static readonly DnsName Origin = DnsName.Parse("example.");

    [Fact]
    public void CommonTypedRecordsUseIndependentWireValues()
    {
        var zone = ZoneMasterFileCodec.Import(Origin, Header + """
            ns A 192.0.2.7
            www 60 IN A 192.0.2.42
                IN AAAA 2001:db8::42
            mail IN 120 MX 10 mx.example.
            alias CNAME www
            7 PTR Host.External.
            old DNAME new
            _service._tcp SRV 1 2 443 target
            txt TXT "a;b( c )" "\000\255\"\\" empty
            @ CAA 0 issue "ca.example; policy=1"
            child NS ns.child
                  DS 12345 8 2 ( 000102030405060708090a0b0c0d0e0f
                                101112131415161718191a1b1c1d1e1f )
            $ORIGIN sub
            leaf A 198.51.100.2
            """);
        Assert.Equal(999u, zone.Soa.GetSoaSerial());
        var soa = zone.Soa.GetData();
        Assert.Equal(new uint[] { 999, 3600, 900, 604800, 60 }, Enumerable.Range(0, 5).Select(index => BinaryPrimitives.ReadUInt32BigEndian(soa.AsSpan(soa.Length - 20 + index * 4))));
        Assert.Equal(new byte[] { 192, 0, 2, 42 }, Record(zone, "www.example.", 1).GetData());
        Assert.Equal(Convert.FromHexString("20010db8000000000000000000000042"), Record(zone, "www.example.", 28).GetData());
        Assert.Equal(60u, Record(zone, "www.example.", 1).Ttl);
        Assert.Equal(300u, Record(zone, "www.example.", 28).Ttl);
        Assert.Equal(new byte[] { 0, 10 }.Concat(DnsName.Parse("mx.example.").ToWire()), Record(zone, "mail.example.", 15).GetData());
        Assert.Equal(DnsName.Parse("www.example.").ToWire(), Record(zone, "alias.example.", 5).GetData());
        Assert.Equal(Convert.FromHexString("04486f73740845787465726e616c00"), Record(zone, "7.example.", 12).GetData());
        Assert.Equal(new byte[] { 0, 1, 0, 2, 1, 187 }.Concat(DnsName.Parse("target.example.").ToWire()), Record(zone, "_service._tcp.example.", 33).GetData());
        Assert.Equal(new byte[] { 8, 97, 59, 98, 40, 32, 99, 32, 41, 4, 0, 255, 34, 92, 5, 101, 109, 112, 116, 121 }, Record(zone, "txt.example.", 16).GetData());
        Assert.Equal(new byte[] { 198, 51, 100, 2 }, Record(zone, "leaf.sub.example.", 1).GetData());
    }

    [Fact]
    public void EscapesQuotedCommentsAndMultilineStringsRetainOctetsAndWireCase()
    {
        var zone = ZoneMasterFileCodec.Import(Origin, Header + """
            MiXeD\046\000\255 TXT "a;b( c )" "\000\255\"\\" ""
            \@ TXT "x"
            \$INCLUDE TXT "literal"
            """ + "\nmulti TXT \"first\r\nsecond\"\n");
        var name = DnsName.Parse("mixed\\046\\000\\255.example.");
        var record = Assert.Single(zone.GetRecords(name));
        Assert.Equal(Convert.FromHexString("084d695865442e00ff076578616d706c6500"), record.GetOwnerWire());
        Assert.Equal(new byte[] { 8, 97, 59, 98, 40, 32, 99, 32, 41, 4, 0, 255, 34, 92, 0 }, record.GetData());
        Assert.Equal(new byte[] { 13 }.Concat("first\r\nsecond".Select(character => (byte)character)), Record(zone, "multi.example.", 16).GetData());
        Assert.Single(zone.GetRecords(DnsName.Parse("\\064.example.")));
        Assert.Single(zone.GetRecords(DnsName.Parse("\\036include.example.")));
        var exported = ZoneMasterFileCodec.Export(zone);
        var imported = ZoneMasterFileCodec.Import(Origin, exported);
        Assert.Equal(ZoneBundleCodec.Compile(Guid.NewGuid(), 1, zone).GetPayload(), ZoneBundleCodec.Compile(Guid.NewGuid(), 1, imported).GetPayload());
    }

    [Fact]
    public void GenericKnownUnknownAndServiceBindingRecordsRoundTripLosslessly()
    {
        var zone = ZoneMasterFileCodec.Import(Origin, Header + """
            www CLASS1 TYPE1 \# 4 c000022a
            empty TYPE65280 \# 0
            binary TYPE65281 \# 8 00ff ( dead BEEF 1234 )
            svc TYPE64 \# 7 000100fde80000
            web HTTPS \# 16 000100000100030268320003000201bb
            """);
        Assert.Equal(new byte[] { 192, 0, 2, 42 }, Record(zone, "www.example.", 1).GetData());
        Assert.Empty(Record(zone, "empty.example.", 65280).GetData());
        Assert.Equal(Convert.FromHexString("00ffdeadbeef1234"), Record(zone, "binary.example.", 65281).GetData());
        var exported = ZoneMasterFileCodec.Export(zone);
        Assert.Contains("TYPE65280 \\# 0\n", exported, StringComparison.Ordinal);
        Assert.Contains("TYPE65 \\#", exported, StringComparison.Ordinal);
        var rebuilt = ZoneMasterFileCodec.Import(Origin, exported);
        Assert.Equal(ZoneBundleCodec.Compile(Guid.NewGuid(), 1, zone).GetPayload(), ZoneBundleCodec.Compile(Guid.NewGuid(), 1, rebuilt).GetPayload());
        Assert.Equal(exported, ZoneMasterFileCodec.Export(rebuilt));
    }

    [Fact]
    public void TtlDefaultsAndOwnerReuseFollowLogicalEntries()
    {
        var zone = ZoneMasterFileCodec.Import(Origin, Header + """
            host 1h IN A 192.0.2.1
                ; no owner change
                AAAA 2001:db8::1
            $TTL 1d2h3m4s
            leaf TXT "value"
            """);
        Assert.Equal(3600u, Record(zone, "host.example.", 1).Ttl);
        Assert.Equal(300u, Record(zone, "host.example.", 28).Ttl);
        Assert.Equal(93784u, Record(zone, "leaf.example.", 16).Ttl);
        var legacy = ZoneMasterFileCodec.Import(Origin, Header.Replace("$TTL 300\n", "", StringComparison.Ordinal).Replace("@ IN SOA", "@ 60 IN SOA", StringComparison.Ordinal) + "host A 192.0.2.1\n");
        Assert.Equal(60u, Record(legacy, "host.example.", 1).Ttl);
        Assert.Equal(ZoneMasterFileCodec.MaximumTextBytes, ProtocolVersionBound());
    }

    [Theory]
    [InlineData("$INCLUDE /etc/passwd")]
    [InlineData("$GENERATE 1-10 host$ A 192.0.2.$")]
    [InlineData("$UNKNOWN data")]
    [InlineData("$ORIGIN outside.")]
    [InlineData("host CH A 192.0.2.1")]
    [InlineData("host CLASS3 TYPE1 \\# 4 c0000201")]
    [InlineData("host 300 400 IN A 192.0.2.1")]
    [InlineData("host IN IN A 192.0.2.1")]
    [InlineData("host A 127.1")]
    [InlineData("host AAAA fe80::1%2")]
    [InlineData("host TYPE65280 \\# 2 000102")]
    [InlineData("host TYPE65280 \\# 1 a b")]
    [InlineData("host TYPE65280 \\# 1 gg")]
    [InlineData("host TYPE1 \\# 3 c00002")]
    [InlineData("host TYPE0 \\# 0")]
    [InlineData("host TYPE41 \\# 0")]
    [InlineData("host TYPE252 \\# 0")]
    [InlineData("host SVCB 1 . alpn=h2")]
    [InlineData("host TXT \"unterminated")]
    [InlineData("host TXT \"a\"joined")]
    [InlineData("host TXT \\25")]
    [InlineData("host TXT \\999")]
    [InlineData("host TXT ( ( \"a\" ) )")]
    [InlineData("host TXT ( \"a\"")]
    [InlineData("host TXT \"a\" )")]
    [InlineData("host 2147483648 A 192.0.2.1")]
    [InlineData("host 99999999999999999999 A 192.0.2.1")]
    [InlineData("host 50000w A 192.0.2.1")]
    [InlineData("@ DS 12345 8 2 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")]
    [InlineData("other DS 12345 8 2 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")]
    [InlineData("host CNAME target\nhost A 192.0.2.1")]
    [InlineData("outside.test. A 192.0.2.1")]
    [InlineData("host A 192.0.2.1\nhost A 192.0.2.1")]
    [InlineData("host A 192.0.2.1\nhost 301 A 192.0.2.2")]
    public void UnsafeMalformedOrInvalidResultingZonesAreRejected(string input) => Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, Header + input));

    [Fact]
    public void TextNameRecordAndExportBoundsRejectWithoutPartialResults()
    {
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, new string(' ', ZoneMasterFileCodec.MaximumTextBytes + 1)));
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, Header + "host TXT \"é\""));
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, Header + new string('a', 64) + " A 192.0.2.1"));
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, Header + "host TXT \"" + new string('a', 256) + "\""));
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, "  A 192.0.2.1"));
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, Header.Replace("$TTL 300\n", "", StringComparison.Ordinal)));
        var tooMany = Header + string.Concat(Enumerable.Range(0, 10_000).Select(index => "host" + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + " A 192.0.2.1\n"));
        Assert.Throws<FormatException>(() => ZoneMasterFileCodec.Import(Origin, tooMany));
        var zone = AuthorityFixture.Zone(Enumerable.Range(0, 10).Select(index => AuthorityFixture.Record("host" + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".example.", 65280, new byte[60_000])).ToArray());
        Assert.Throws<InvalidOperationException>(() => ZoneMasterFileCodec.Export(zone));
    }

    [Fact]
    public void RootOriginAndEscapedTerminalDotAreUnambiguous()
    {
        var root = DnsName.Parse(".");
        var zone = ZoneMasterFileCodec.Import(root, "$TTL 300\n@ SOA ns. hostmaster. 1 3600 600 86400 30\n  NS ns.\nns A 192.0.2.1\na\\. TXT \"root child with a literal dot\"\n");
        Assert.Single(zone.GetRecords(DnsName.Parse("a\\046.")));
        var exported = ZoneMasterFileCodec.Export(zone);
        Assert.StartsWith("$ORIGIN .\n", exported, StringComparison.Ordinal);
        var rebuilt = ZoneMasterFileCodec.Import(root, exported);
        Assert.Equal(ZoneBundleCodec.Compile(Guid.NewGuid(), 1, zone).GetPayload(), ZoneBundleCodec.Compile(Guid.NewGuid(), 1, rebuilt).GetPayload());
    }

    private static DnsRecord Record(AuthoritativeZone zone, string name, ushort type) => Assert.Single(zone.GetRecords(DnsName.Parse(name)), record => record.Type == type);
    private static int ProtocolVersionBound() => Mk8.Dns.Contracts.ProtocolVersion.MaximumZoneFileBytes;
}
