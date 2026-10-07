using System.Globalization;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.ConformanceTests;

public sealed class DnssecConformanceTests
{
    // Fixed public examples from RFC 6605 section 6.1, independently verified.
    private const string PublicKey = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";
    private const string FixturePkcs8 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mShRANCAAQaiMiGFdQ3+7i/nhlCoZKfKFYnBq5sK9OZ57G/ttHp51uStKpCkXrhxhtwHvA1w/574wCcuv5aL3ExbJAtzw0A";
    private const string SignatureHex = "00010d0300000e104c88b1374c63c737d960076578616d706c65036e657400ab1eb02d8aa687e97da0229337aa8873e6f0eb26be289f28333d183f5d3b7a95c0c869adfb748daee3c5286eed6682c12e5533186baced9c26c167a9ebae950b";
    private static readonly DnsName Origin = DnsName.Parse("example.net.");
    private static readonly DnsName Owner = DnsName.Parse("www.example.net.");

    [Fact]
    public void Rfc6605PublicDnskeyTagAndSha256DsMatchFixedBytes()
    {
        var key = DnssecKeys.CreateDnskey(Origin, 3600, Convert.FromBase64String(PublicKey));
        Assert.Equal((ushort)55648, DnssecKeys.KeyTag(key));
        Assert.Equal(Convert.FromHexString("d9600d02b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17"), DnssecKeys.CreateDs(key, 3600).GetData());
        Assert.Equal(Origin, DnssecKeys.CreateDs(key, 3600).Owner);
    }

    [Fact]
    public void Rfc6605ARecordCanonicalWireMatchesFixedOracle()
    {
        var record = new DnsRecord(Owner, 1, 1, new byte[] { 192, 0, 2, 1 });
        Assert.Equal(Convert.FromHexString("03777777076578616d706c65036e6574000001000100000e100004c0000201"), DnssecCanonical.GetRrset([record], 3600, 3));
    }

    [Theory]
    [InlineData("20100812100439", true, 3600u)]
    [InlineData("20100813100439", true, 3600u)]
    [InlineData("20100909100429", true, 10u)]
    [InlineData("20100909100439", true, 0u)]
    [InlineData("20100812100438", false, 0u)]
    [InlineData("20100909100440", false, 0u)]
    public void Rfc6605SignatureVerifiesWithInclusiveSerialTimesAndTtlCap(string time, bool valid, uint ttl)
    {
        var record = new DnsRecord(Owner, 1, 3600, new byte[] { 192, 0, 2, 1 });
        var signature = new DnsRecord(Owner, 46, 3600, Convert.FromHexString(SignatureHex));
        var key = DnssecKeys.CreateDnskey(Origin, 3600, Convert.FromBase64String(PublicKey));
        Assert.Equal(valid, DnssecRrsetVerifier.TryVerify([record], signature, key, Stamp(time), new EcdsaP256DnssecVerifier(), out var capped));
        Assert.Equal(ttl, capped);
    }

    [Fact]
    public void Rfc6605CachedTtlsDoNotChangeTheAuthenticatedOriginalData()
    {
        var record = new DnsRecord(Owner, 1, 45, new byte[] { 192, 0, 2, 1 });
        var signature = new DnsRecord(Owner, 46, 90, Convert.FromHexString(SignatureHex));
        var key = DnssecKeys.CreateDnskey(Origin, 3600, Convert.FromBase64String(PublicKey));
        Assert.True(DnssecRrsetVerifier.TryVerify([record], signature, key, Stamp("20100813100439"), new EcdsaP256DnssecVerifier(), out var ttl));
        Assert.Equal(45u, ttl);
    }

    [Fact]
    public void Rfc6605PublicPrivateFixtureImportsAndSignsWithMatchingPublicPoint()
    {
        using var key = EcdsaP256DnssecSigningKey.ImportPkcs8(Convert.FromBase64String(FixturePkcs8));
        Assert.Equal(Convert.FromBase64String(PublicKey), key.GetPublicKey());
        var record = new DnsRecord(Owner, 1, 3600, new byte[] { 192, 0, 2, 1 });
        var dnskey = DnssecKeys.CreateDnskey(Origin, 3600, key.GetPublicKey());
        var verifier = new EcdsaP256DnssecVerifier();
        var window = new DnssecSignatureWindow(Stamp("20100812100439"), Stamp("20100909100439"));
        var signature = DnssecRrsetSigner.Sign([record], dnskey, key, verifier, window);
        Assert.True(DnssecRrsetVerifier.TryVerify([record], signature, dnskey, window.Inception, verifier, out var ttl));
        Assert.Equal(3600u, ttl);
    }

    [Fact]
    public void Rfc4034CanonicalNameOrderIncludesBinaryLabelsAndAncestorFirst()
    {
        string[] ordered = ["example.", "a.example.", "yljkjljk.a.example.", "z.a.example.", "zabc.a.example.", "z.example.", "\\001.z.example.", "*.z.example.", "\\200.z.example."];
        var input = ordered.Reverse().Select(DnsName.Parse).Append(DnsName.Parse("Z.a.EXAMPLE.")).Distinct();
        Assert.Equal(ordered, input.OrderBy(name => name, DnssecNameOrder.Instance).Select(name => name.ToString()), StringComparer.Ordinal);
    }

    [Fact]
    public void Rfc4034BitmapMatchesFixedMultiWindowBytes()
    {
        ushort[] types = [1, 2, 6, 16, 46, 47, 48, 257, 65535];
        var wire = Convert.FromHexString("000762008000000380010140ff200000000000000000000000000000000000000000000000000000000000000001");
        Assert.Equal(wire, NsecBitmap.Encode(types));
        Assert.Equal(types, NsecBitmap.Decode(wire));
    }

    [Theory]
    [InlineData(0, 1, 0, true)]
    [InlineData(0, 1, 1, true)]
    [InlineData(0, 1, 2, false)]
    [InlineData(4294967294, 1, 4294967295, true)]
    [InlineData(4294967294, 1, 0, true)]
    [InlineData(4294967294, 1, 1, true)]
    [InlineData(4294967294, 1, 2, false)]
    [InlineData(4294967294, 1, 4294967293, false)]
    public void Rfc1982SignatureIntervalsAdvanceAcrossWrap(uint inception, uint expiration, uint now, bool valid) => Assert.Equal(valid, new DnssecSignatureWindow(inception, expiration).Contains(now));

    private static uint Stamp(string text) => checked((uint)DateTimeOffset.ParseExact(text, "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUnixTimeSeconds());
}
