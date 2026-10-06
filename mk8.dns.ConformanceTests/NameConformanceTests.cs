using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.ConformanceTests;

public sealed class NameConformanceTests
{
    public static TheoryData<string, string> WireVectors => new()
    {
        { ".", "00" },
        { "example.org.", "076578616d706c65036f726700" },
        { "WWW.Example.Org.", "03777777076578616d706c65036f726700" },
        { "a\\.b.", "03612e6200" },
        { "\\000.\\255.", "010001ff00" },
        { "_acme-challenge.example.org.", "0f5f61636d652d6368616c6c656e6765076578616d706c65036f726700" },
    };

    [Theory]
    [MemberData(nameof(WireVectors))]
    public void Rfc1035UncompressedNamesMatchIndependentOctetVectors(string text, string hex)
    {
        var name = DnsName.Parse(text);
        var expected = Convert.FromHexString(hex);
        Assert.Equal(expected, name.ToWire());
        Assert.Equal(name, DnsName.FromWire(expected));
        Assert.Equal(name, DnsName.Parse(name.ToString()));
    }

    [Theory]
    [InlineData("example.org")]
    [InlineData("a..org.")]
    [InlineData("é.org.")]
    [InlineData("\\256.")]
    [InlineData("\\1.")]
    [InlineData("a\\.")]
    public void MalformedOrRelativeNamesAreRejected(string text) => Assert.Throws<FormatException>(() => DnsName.Parse(text));

    [Theory]
    [InlineData("")]
    [InlineData("c000")]
    [InlineData("0100")]
    [InlineData("0000")]
    [InlineData("40")]
    public void TruncatedCompressedAndOversizedLabelsAreRejected(string hex) => Assert.Throws<FormatException>(() => DnsName.FromWire(Convert.FromHexString(hex)));

    [Fact]
    public void LabelAndNameLimitsUseOctetsIncludingTheRoot()
    {
        var maximum = new string('a', 63) + "." + new string('b', 63) + "." + new string('c', 63) + "." + new string('d', 61) + ".";
        Assert.Equal(255, DnsName.Parse(maximum).ToWire().Length);
        Assert.Throws<FormatException>(() => DnsName.Parse(new string('a', 64) + "."));
        Assert.Throws<FormatException>(() => DnsName.Parse(maximum.Insert(maximum.Length - 1, "d")));
    }
}
