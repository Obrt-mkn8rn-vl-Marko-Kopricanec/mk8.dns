using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Mk8.Dns.Domain;

public sealed class DnssecRsaPublicKey
{
    private readonly byte[] wire;
    private readonly int exponentOffset;
    private readonly int modulusOffset;

    public DnssecRsaPublicKey(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length is < 66 or > 1027)
            throw new FormatException("Invalid bounded RSA DNSSEC public key.");
        wire = publicKey.ToArray();
        ReadOnlySpan<byte> data = wire;
        exponentOffset = data[0] == 0 ? 3 : 1;
        var exponentLength = exponentOffset == 3 ? BinaryPrimitives.ReadUInt16BigEndian(data[1..]) : data[0];
        modulusOffset = exponentOffset + exponentLength;
        if (exponentLength is < 1 or > 512 || exponentOffset == 3 && exponentLength <= 255 || modulusOffset >= data.Length)
            throw new FormatException("Invalid RSA exponent length.");
        var exponent = data.Slice(exponentOffset, exponentLength);
        var modulus = data[modulusOffset..];
        if (exponent[0] == 0 || modulus.Length is < 64 or > 512 || modulus[0] == 0
            || (exponent[^1] & 1) == 0 || exponent.Length == 1 && exponent[0] < 3 || (modulus[^1] & 1) == 0
            || exponent.Length > modulus.Length || exponent.Length == modulus.Length && exponent.SequenceCompareTo(modulus) >= 0)
            throw new FormatException("Invalid RSA public integers.");
        ModulusBits = (modulus.Length - 1) * 8 + 32 - BitOperations.LeadingZeroCount((uint)modulus[0]);
        if (ModulusBits is < 512 or > 4096)
            throw new FormatException("RSA modulus is outside the 512–4096-bit validation profile.");
    }

    public int ModulusBits { get; }
    public int SignatureSize => wire.Length - modulusOffset;
    public byte[] GetExponent() => wire[exponentOffset..modulusOffset];
    public byte[] GetModulus() => wire[modulusOffset..];
    public byte[] ToWire() => (byte[])wire.Clone();

    public static bool TryParse(ReadOnlySpan<byte> publicKey, [NotNullWhen(true)] out DnssecRsaPublicKey? key)
    {
        key = null;
        try { key = new DnssecRsaPublicKey(publicKey); return true; }
        catch (FormatException) { return false; }
    }
}
