using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecCanonicalTests
{
    [Theory]
    [InlineData(2, 0, 1, 0)]
    [InlineData(3, 0, 1, 0)]
    [InlineData(4, 0, 1, 0)]
    [InlineData(5, 0, 1, 0)]
    [InlineData(7, 0, 1, 0)]
    [InlineData(8, 0, 1, 0)]
    [InlineData(9, 0, 1, 0)]
    [InlineData(12, 0, 1, 0)]
    [InlineData(39, 0, 1, 0)]
    [InlineData(6, 0, 2, 20)]
    [InlineData(14, 0, 2, 0)]
    [InlineData(17, 0, 2, 0)]
    [InlineData(15, 2, 1, 0)]
    [InlineData(18, 2, 1, 0)]
    [InlineData(21, 2, 1, 0)]
    [InlineData(36, 2, 1, 0)]
    [InlineData(26, 2, 2, 0)]
    [InlineData(33, 6, 1, 0)]
    [InlineData(24, 18, 1, 4)]
    [InlineData(46, 18, 1, 4)]
    [InlineData(30, 0, 1, 4)]
    public void LegacyNamesFoldWithoutChangingHeadersOrTails(ushort type, int prefix, int names, int tail)
    {
        var before = Enumerable.Repeat((byte)'Z', prefix).ToArray();
        var after = Enumerable.Repeat((byte)'Y', tail).ToArray();
        var original = before.Concat(Enumerable.Range(0, names).SelectMany(_ => DnssecFixture.Name("Ns.EXAMPLE.", upper: true))).Concat(after).ToArray();
        var canonical = before.Concat(Enumerable.Range(0, names).SelectMany(_ => DnssecFixture.Name("ns.example."))).Concat(after).ToArray();
        var record = new DnsRecord(DnssecFixture.Origin, type, 3600, original);
        Assert.Equal(canonical, DnssecCanonical.GetRdata(record));
        Assert.Equal(original, record.GetData());
    }

    [Fact]
    public void NaptrFoldsOnlyReplacementAndA6FoldsOnlyPrefixName()
    {
        byte[] fields = [0, 1, 0, 2, 1, (byte)'U', 3, (byte)'S', (byte)'I', (byte)'P', 3, (byte)'A', (byte)'B', (byte)'C'];
        var naptr = new DnsRecord(DnssecFixture.Origin, 35, 300, [.. fields, .. DnssecFixture.Name("Ns.example.", upper: true)]);
        Assert.Equal([.. fields, .. DnssecFixture.Name("ns.example.")], DnssecCanonical.GetRdata(naptr));
        var a6 = new DnsRecord(DnssecFixture.Origin, 38, 300, [64, .. Enumerable.Repeat((byte)'Z', 8), .. DnssecFixture.Name("ns.example.", upper: true)]);
        Assert.Equal(new byte[] { 64 }.Concat(Enumerable.Repeat((byte)'Z', 8)).Concat(DnssecFixture.Name("ns.example.")), DnssecCanonical.GetRdata(a6));
        var full = new DnsRecord(DnssecFixture.Origin, 38, 300, [0, .. new byte[16]]);
        Assert.Equal(full.GetData(), DnssecCanonical.GetRdata(full));
    }

    [Theory]
    [InlineData(13)]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(65280)]
    public void TextNewAndUnknownTypesStayByteExact(ushort type)
    {
        byte[] data = type switch
        {
            16 => [3, (byte)'A', (byte)'B', (byte)'C'],
            64 or 65 => [0, 1, .. DnssecFixture.Name("Target.example.", upper: true)],
            _ => DnssecFixture.Name("Opaque.example.", upper: true),
        };
        var record = new DnsRecord(DnssecFixture.Origin, type, 300, data);
        var canonical = DnssecCanonical.GetRdata(record);
        Assert.Equal(data, canonical);
        canonical[0] ^= 1;
        Assert.Equal(data, record.GetData());
    }

    [Fact]
    public void NsecPreservesNextNameCaseAndValidatesTheBitmap()
    {
        byte[] data = [.. DnssecFixture.Name("Next.example.", upper: true), 0, 1, 0x40];
        Assert.Equal(data, DnssecCanonical.GetRdata(new DnsRecord(DnssecFixture.Origin, 47, 300, data)));
        Assert.Throws<FormatException>(() => DnssecCanonical.GetRdata(new DnsRecord(DnssecFixture.Origin, 47, 300, [.. DnssecFixture.Name("next.example."), 0, 1, 0])));
    }

    [Theory]
    [InlineData(3, "")]
    [InlineData(3, "c000")]
    [InlineData(3, "034100")]
    [InlineData(3, "0000")]
    [InlineData(14, "00")]
    [InlineData(18, "0000")]
    [InlineData(26, "000000")]
    [InlineData(24, "00000000000000000000000000000000000000")]
    [InlineData(30, "00")]
    [InlineData(35, "000000000141")]
    [InlineData(38, "81")]
    [InlineData(38, "00")]
    [InlineData(38, "8000ff")]
    public void MalformedLegacyNamesAndFieldsFailClosed(ushort type, string hex) => Assert.Throws<FormatException>(() => DnssecCanonical.GetRdata(new DnsRecord(DnssecFixture.Origin, type, 300, Convert.FromHexString(hex))));

    [Fact]
    public void RrsetSortsByOctetsAndShorterPrefixBeforeLongerData()
    {
        DnsRecord[] records = [new(DnssecFixture.Origin, 65280, 1, [2]), new(DnssecFixture.Origin, 65280, 2, [1, 0]), new(DnssecFixture.Origin, 65280, 3, [1])];
        var wire = DnssecCanonical.GetRrset(records, 3600, 1);
        var offset = 0;
        List<byte[]> values = [];
        while (offset < wire.Length)
        {
            offset += DnssecFixture.NameEnd(wire[offset..]);
            Assert.Equal(3600u, BinaryPrimitives.ReadUInt32BigEndian(wire.AsSpan(offset + 4)));
            var length = BinaryPrimitives.ReadUInt16BigEndian(wire.AsSpan(offset + 8));
            values.Add(wire.AsSpan(offset + 10, length).ToArray());
            offset += 10 + length;
        }
        Assert.Equal(new byte[] { 1 }, values[0]);
        Assert.Equal(new byte[] { 1, 0 }, values[1]);
        Assert.Equal(new byte[] { 2 }, values[2]);
        Assert.Equal(wire, DnssecCanonical.GetRrset(records.Reverse().ToArray(), 3600, 1));
    }

    [Fact]
    public void DuplicateFoldedNamesAndMixedOwnerTypeAreRejected()
    {
        var a = new DnsRecord(DnssecFixture.Origin, 2, 300, DnssecFixture.Name("ns.example."));
        var b = new DnsRecord(DnssecFixture.Origin, 2, 300, DnssecFixture.Name("ns.example.", upper: true));
        Assert.Throws<FormatException>(() => DnssecCanonical.GetRrset([a, b], 300, 1));
        Assert.Throws<ArgumentException>(() => DnssecCanonical.GetRrset([a, a.WithOwner(DnsName.Parse("other.example."))], 300, 1));
        Assert.Throws<ArgumentException>(() => DnssecCanonical.GetRrset([a, DnssecFixture.A("example.")], 300, 1));
        Assert.Throws<ArgumentException>(() => DnssecCanonical.GetRrset([null!], 300, 1));
        Assert.Throws<ArgumentException>(() => DnssecCanonical.GetRrset([], 300, 1));
        Assert.Throws<ArgumentException>(() => DnssecCanonical.GetRrset([a], uint.MaxValue, 1));
        Assert.Throws<FormatException>(() => DnssecCanonical.GetRrset([a], 300, 2));
    }

    [Fact]
    public void ExpandedWildcardOwnerIsReconstructedAndByteBoundsApply()
    {
        var original = DnssecFixture.A("*.example.");
        Assert.Equal(DnssecCanonical.GetRrset([original], 300, 1), DnssecCanonical.GetRrset([original.WithOwner(DnsName.Parse("deep.host.example."))], 300, 1));
        var huge = new DnsRecord(DnssecFixture.Origin, 65280, 300, new byte[65535]);
        Assert.Throws<ArgumentException>(() => DnssecCanonical.GetRrset(Enumerable.Repeat(huge, 17).ToArray(), 300, 1));
        Assert.Throws<ArgumentException>(() => DnssecCanonical.GetRrset(Enumerable.Repeat(original, 10001).ToArray(), 300, 1));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(41)]
    [InlineData(249)]
    [InlineData(250)]
    [InlineData(251)]
    [InlineData(252)]
    [InlineData(253)]
    [InlineData(254)]
    [InlineData(255)]
    public void PseudoTypesCannotBeProduced(ushort type) => Assert.Throws<ArgumentException>(() => NsecBitmap.Encode([type]));

    [Theory]
    [InlineData("")]
    [InlineData("00")]
    [InlineData("0000")]
    [InlineData("0021")]
    [InlineData("000240")]
    [InlineData("00024000")]
    [InlineData("000140000140")]
    [InlineData("010140000140")]
    [InlineData("000140ff")]
    public void MalformedNonminimalOrUnorderedBitmapsAreRejected(string hex) => Assert.Throws<FormatException>(() => NsecBitmap.Decode(Convert.FromHexString(hex)));

    [Fact]
    public void PseudoBitsAreIgnoredOnReadAndEncoderIsCanonical()
    {
        Assert.Equal(new ushort[] { 1 }, NsecBitmap.Decode([0, 1, 0xc0]));
        Assert.Equal(NsecBitmap.Encode([1, 257, 65535]), NsecBitmap.Encode([65535, 257, 1, 1]));
        Assert.Throws<ArgumentException>(() => NsecBitmap.Encode([]));
        Assert.Throws<ArgumentException>(() => NsecBitmap.Encode(Enumerable.Repeat((ushort)1, 65537)));
        Assert.Throws<FormatException>(() => NsecBitmap.Decode(new byte[8705]));
    }

    [Theory]
    [InlineData(0u, 0u)]
    [InlineData(1u, 0u)]
    [InlineData(0u, 2147483648u)]
    [InlineData(2147483648u, 0u)]
    public void AmbiguousOrEmptySignatureWindowsAreRejected(uint first, uint last) => Assert.Throws<ArgumentException>(() => new DnssecSignatureWindow(first, last));

    [Fact]
    public void NameOrderingHandlesRootNullsCaseAndNonAsciiOctets()
    {
        var order = DnssecNameOrder.Instance;
        Assert.Equal(0, order.Compare(null, null));
        Assert.True(order.Compare(null, DnssecFixture.Origin) < 0);
        Assert.True(order.Compare(DnssecFixture.Origin, null) > 0);
        Assert.True(order.Compare(DnsName.Parse("."), DnssecFixture.Origin) < 0);
        Assert.Equal(0, order.Compare(DnsName.Parse("EXAMPLE."), DnssecFixture.Origin));
        Assert.True(order.Compare(DnsName.Parse("\\192.example."), DnsName.Parse("\\224.example.")) < 0);
    }
}
