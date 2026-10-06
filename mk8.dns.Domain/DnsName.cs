using System.Globalization;
using System.Text;

namespace Mk8.Dns.Domain;

public sealed class DnsName : IEquatable<DnsName>
{
    private readonly byte[] wire;

    private DnsName(byte[] wire)
    {
        this.wire = wire;
    }

    public static DnsName Parse(string text)
    {
        ArgumentException.ThrowIfNullOrEmpty(text);
        if (string.Equals(text, ".", StringComparison.Ordinal))
            return new DnsName([0]);
        if (!text.EndsWith('.'))
            throw new FormatException("DNS names must be absolute.");

        List<byte> encoded = [0];
        var labelStart = 0;
        for (var index = 0; index < text.Length; index++)
        {
            var value = text[index];
            if (value == '.')
            {
                var length = encoded.Count - labelStart - 1;
                if (length is < 1 or > 63)
                    throw new FormatException("DNS labels must contain between 1 and 63 octets.");
                encoded[labelStart] = (byte)length;
                encoded.Add(0);
                labelStart = encoded.Count - 1;
                continue;
            }

            if (value == '\\')
            {
                if (++index >= text.Length)
                    throw new FormatException("Incomplete DNS escape.");
                value = text[index];
                if (char.IsAsciiDigit(value))
                {
                    if (index + 2 >= text.Length || !char.IsAsciiDigit(text[index + 1]) || !char.IsAsciiDigit(text[index + 2]))
                        throw new FormatException("Numeric DNS escapes require three decimal digits.");
                    var octet = ((value - '0') * 100) + ((text[index + 1] - '0') * 10) + text[index + 2] - '0';
                    if (octet > byte.MaxValue)
                        throw new FormatException("DNS escape exceeds one octet.");
                    value = (char)octet;
                    index += 2;
                }
                else if (value > 127)
                {
                    throw new FormatException("Use octet escapes or IDNA A-labels for non-ASCII names.");
                }
            }
            else if (value is < '!' or > '~')
            {
                throw new FormatException("Use octet escapes or IDNA A-labels for non-ASCII names.");
            }

            encoded.Add(FoldAscii((byte)value));
            if (encoded.Count - labelStart - 1 > 63 || encoded.Count > 255)
                throw new FormatException("DNS name exceeds its wire bounds.");
        }

        if (encoded.Count > 255 || encoded[^1] != 0 || labelStart != encoded.Count - 1)
            throw new FormatException("DNS names must end in the root label.");
        return new DnsName([.. encoded]);
    }

    public static DnsName FromWire(ReadOnlySpan<byte> uncompressedName)
    {
        if (uncompressedName.IsEmpty || uncompressedName.Length > 255)
            throw new FormatException("Invalid DNS wire name length.");
        var copy = uncompressedName.ToArray();
        var offset = 0;
        while (offset < copy.Length)
        {
            var length = copy[offset++];
            if (length == 0)
            {
                if (offset != copy.Length)
                    throw new FormatException("Trailing bytes after the root label.");
                return new DnsName(copy);
            }
            if (length > 63 || offset + length >= copy.Length)
                throw new FormatException("Invalid uncompressed DNS label.");
            for (var index = 0; index < length; index++)
                copy[offset + index] = FoldAscii(copy[offset + index]);
            offset += length;
        }

        throw new FormatException("Missing DNS root label.");
    }

    public byte[] ToWire() => (byte[])wire.Clone();

    public int LabelCount
    {
        get
        {
            var count = 0;
            for (var offset = 0; wire[offset] != 0; offset += wire[offset] + 1)
                count++;
            return count;
        }
    }

    public DnsName Parent => wire[0] == 0 ? this : FromWire(wire.AsSpan(wire[0] + 1));

    public bool IsSubdomainOf(DnsName ancestor)
    {
        ArgumentNullException.ThrowIfNull(ancestor);
        for (var offset = 0; ; offset += wire[offset] + 1)
        {
            if (wire.AsSpan(offset).SequenceEqual(ancestor.wire))
                return true;
            if (wire[offset] == 0)
                return false;
        }
    }

    public DnsName PrependLabel(ReadOnlySpan<byte> label)
    {
        if (label.Length is < 1 or > 63 || label.Length + wire.Length + 1 > 255)
            throw new FormatException("DNS name exceeds its wire bounds.");
        var result = new byte[label.Length + wire.Length + 1];
        result[0] = (byte)label.Length;
        label.CopyTo(result.AsSpan(1));
        wire.CopyTo(result, label.Length + 1);
        return FromWire(result);
    }

    public bool Equals(DnsName? other) => other is not null && wire.AsSpan().SequenceEqual(other.wire);

    public override bool Equals(object? obj) => obj is DnsName other && Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(wire);
        return hash.ToHashCode();
    }

    public override string ToString()
    {
        if (wire.Length == 1)
            return ".";
        var result = new StringBuilder();
        var offset = 0;
        while (wire[offset] != 0)
        {
            var length = wire[offset++];
            for (var index = 0; index < length; index++)
            {
                var octet = wire[offset++];
                if (octet is >= (byte)'!' and <= (byte)'~' && octet is not (byte)'.' and not (byte)'\\' and not (byte)';' and not (byte)'(' and not (byte)')' and not (byte)'"' and not (byte)'@' and not (byte)'$')
                    result.Append((char)octet);
                else
                    result.Append('\\').Append(octet.ToString("D3", CultureInfo.InvariantCulture));
            }
            result.Append('.');
        }
        return result.ToString();
    }

    private static byte FoldAscii(byte value) => value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;
}
