using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RsaDnssecKeyTests
{
    [Theory]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(512)]
    public void PublicKeyOwnsAllInputAndReturnedIntegerBytes(int width)
    {
        var modulus = Enumerable.Repeat((byte)0x81, width).ToArray();
        byte[] input = [3, 1, 0, 1, .. modulus];
        var key = new DnssecRsaPublicKey(input);
        input.AsSpan().Clear(); key.GetExponent().AsSpan().Clear(); key.GetModulus().AsSpan().Clear(); key.ToWire().AsSpan().Clear();
        Assert.Equal(width * 8, key.ModulusBits);
        Assert.Equal(width, key.SignatureSize);
        Assert.Equal(new byte[] { 1, 0, 1 }, key.GetExponent());
        Assert.Equal(modulus, key.GetModulus());
    }

    [Theory]
    [InlineData(256)]
    [InlineData(511)]
    [InlineData(512)]
    public void ExtendedExponentLengthConsumesExactlyDeclaredUnsignedInteger(int length)
    {
        var exponent = Enumerable.Repeat((byte)1, length).ToArray();
        var header = new byte[3]; BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(1), (ushort)length);
        var modulus = Enumerable.Repeat((byte)0x81, 512).ToArray();
        var key = new DnssecRsaPublicKey([.. header, .. exponent, .. modulus]);
        Assert.Equal(exponent, key.GetExponent());
        Assert.Equal(modulus, key.GetModulus());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    public void NoncanonicalTruncatedOrOutOfBoundsIntegersRefuse(int defect)
    {
        var modulus = Enumerable.Repeat((byte)0x81, 64).ToArray();
        byte[] input = defect switch
        {
            0 => [],
            1 => [0, 1],
            2 => [0, 0, 3, 1, 0, 1, .. modulus], // Nonminimal extended length.
            3 => [1, 0, .. modulus],
            4 => [1, 1, .. modulus],
            5 => [1, 2, .. modulus],
            6 => [3, 1, 0, 1, 0, .. modulus],
            7 => [3, 1, 0, 1, .. modulus[..63]],
            8 => [3, 1, 0, 1, 0x7f, .. modulus[1..]],
            9 => [3, 1, 0, 1, .. modulus[..63], 0x80],
            _ => [3, 1, 0, 1, .. Enumerable.Repeat((byte)0x81, 513)],
        };
        Assert.False(DnssecRsaPublicKey.TryParse(input, out var key));
        Assert.Null(key);
        Assert.Throws<FormatException>(() => new DnssecRsaPublicKey(input));
    }

    [Fact]
    public void ExponentCannotEqualOrExceedModulus()
    {
        var modulus = Enumerable.Repeat((byte)0x81, 64).ToArray();
        Assert.False(DnssecRsaPublicKey.TryParse([64, .. modulus, .. modulus], out _));
        Assert.False(DnssecRsaPublicKey.TryParse([65, .. modulus, 1, .. modulus], out _));
    }
}
