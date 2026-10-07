using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Mk8.Dns.Wire;

internal static class MasterFileData
{
    internal static ushort Type(MasterFileToken token)
    {
        Require(!token.Quoted);
        return token.Text.ToUpperInvariant() switch
        {
            "A" => 1,
            "NS" => 2,
            "CNAME" => 5,
            "SOA" => 6,
            "PTR" => 12,
            "MX" => 15,
            "TXT" => 16,
            "AAAA" => 28,
            "SRV" => 33,
            "DNAME" => 39,
            "DS" => 43,
            "SVCB" => 64,
            "HTTPS" => 65,
            "CAA" => 257,
            var name when name.StartsWith("TYPE", StringComparison.Ordinal) => (ushort)Number(new MasterFileToken(name[4..], false), ushort.MaxValue),
            _ => throw new FormatException("Unsupported master-file type mnemonic or class."),
        };
    }

    internal static byte[] Record(ushort type, IReadOnlyList<MasterFileToken> fields, byte[] origin)
    {
        if (fields.Count != 0 && !fields[0].Quoted && string.Equals(fields[0].Text, "\\#", StringComparison.Ordinal))
            return Generic(fields);
        using var output = new MemoryStream();
        switch (type)
        {
            case 1:
                Require(fields.Count == 1 && !fields[0].Quoted);
                var address = fields[0].Text.Split('.');
                Require(address.Length == 4);
                foreach (var octet in address)
                    output.WriteByte((byte)Number(new MasterFileToken(octet, false), byte.MaxValue));
                break;
            case 28:
                Require(fields.Count == 1 && !fields[0].Quoted && !fields[0].Text.Contains('%', StringComparison.Ordinal));
                Require(IPAddress.TryParse(fields[0].Text, out var ipv6) && ipv6.AddressFamily == AddressFamily.InterNetworkV6);
                output.Write(ipv6!.GetAddressBytes());
                break;
            case 2 or 5 or 12 or 39:
                Require(fields.Count == 1);
                output.Write(Name(fields[0], origin));
                break;
            case 6:
                Require(fields.Count == 7);
                output.Write(Name(fields[0], origin));
                output.Write(Name(fields[1], origin));
                Write32(output, Number(fields[2], uint.MaxValue));
                foreach (var field in fields.Skip(3))
                    Write32(output, Time(field, uint.MaxValue));
                break;
            case 15:
                Require(fields.Count == 2);
                Write16(output, (ushort)Number(fields[0], ushort.MaxValue));
                output.Write(Name(fields[1], origin));
                break;
            case 33:
                Require(fields.Count == 4);
                foreach (var field in fields.Take(3))
                    Write16(output, (ushort)Number(field, ushort.MaxValue));
                output.Write(Name(fields[3], origin));
                break;
            default:
                WriteTextData(output, type, fields);
                break;
        }
        Require(output.Length <= ushort.MaxValue);
        return output.ToArray();
    }

    private static byte[] Generic(IReadOnlyList<MasterFileToken> fields)
    {
        Require(fields.Count >= 2);
        var length = Number(fields[1], ushort.MaxValue);
        var data = Hex(fields.Skip(2));
        Require(data.Length == length);
        return data;
    }

    private static void WriteTextData(Stream output, ushort type, IReadOnlyList<MasterFileToken> fields)
    {
        switch (type)
        {
            case 16:
                Require(fields.Count != 0);
                foreach (var field in fields)
                {
                    var value = Octets(field.Text);
                    Require(value.Length <= byte.MaxValue);
                    output.WriteByte((byte)value.Length);
                    output.Write(value);
                }
                break;
            case 43:
                Require(fields.Count >= 4);
                Write16(output, (ushort)Number(fields[0], ushort.MaxValue));
                output.WriteByte((byte)Number(fields[1], byte.MaxValue));
                output.WriteByte((byte)Number(fields[2], byte.MaxValue));
                output.Write(Hex(fields.Skip(3)));
                break;
            case 257:
                Require(fields.Count == 3);
                output.WriteByte((byte)Number(fields[0], byte.MaxValue));
                var tag = Octets(fields[1].Text);
                Require(tag.Length is >= 1 and <= 15 && tag.All(octet => octet is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9'));
                output.WriteByte((byte)tag.Length);
                output.Write(tag);
                output.Write(Octets(fields[2].Text));
                break;
            default:
                throw new FormatException("This record type requires generic \\# RDATA.");
        }
    }

    internal static byte[] Name(MasterFileToken token, byte[] origin)
    {
        if (!token.Quoted && string.Equals(token.Text, "@", StringComparison.Ordinal))
            return (byte[])origin.Clone();
        if (string.Equals(token.Text, ".", StringComparison.Ordinal))
            return [0];
        Require(token.Text.Length != 0);
        List<byte> wire = [0];
        var labelStart = 0;
        var absolute = false;
        for (var position = 0; position < token.Text.Length; position++)
        {
            var character = token.Text[position];
            if (character == '.')
            {
                Require(wire.Count - labelStart - 1 is > 0 and <= 63);
                wire[labelStart] = (byte)(wire.Count - labelStart - 1);
                labelStart = wire.Count;
                wire.Add(0);
                absolute = position == token.Text.Length - 1;
            }
            else
            {
                wire.Add(Octet(token.Text, ref position));
                Require(wire.Count - labelStart - 1 <= 63);
            }
        }
        if (!absolute)
        {
            Require(wire.Count - labelStart - 1 is > 0 and <= 63);
            wire[labelStart] = (byte)(wire.Count - labelStart - 1);
            wire.AddRange(origin);
        }
        Require(wire.Count <= 255);
        return [.. wire];
    }

    internal static string FormatName(byte[] name)
    {
        if (name.Length == 1)
            return ".";
        var result = new StringBuilder();
        for (var position = 0; name[position] != 0;)
        {
            var length = name[position++];
            for (var index = 0; index < length; index++)
            {
                var octet = name[position++];
                if (octet is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_' or (byte)'*')
                    result.Append((char)octet);
                else
                    result.Append('\\').Append(octet.ToString("D3", CultureInfo.InvariantCulture));
            }
            result.Append('.');
        }
        return result.ToString();
    }

    internal static uint Time(MasterFileToken token, uint maximum)
    {
        Require(!token.Quoted && token.Text.Length != 0);
        ulong total = 0;
        for (var position = 0; position < token.Text.Length;)
        {
            var start = position;
            while (position < token.Text.Length && token.Text[position] is >= '0' and <= '9')
                position++;
            var number = Number(new MasterFileToken(token.Text[start..position], false), maximum);
            var multiplier = position == token.Text.Length ? 1U : char.ToUpperInvariant(token.Text[position++]) switch
            {
                'W' => 604_800U,
                'D' => 86_400U,
                'H' => 3_600U,
                'M' => 60U,
                'S' => 1U,
                _ => throw new FormatException("Invalid master-file time unit."),
            };
            total += (ulong)number * multiplier;
            Require(total <= maximum);
        }
        return (uint)total;
    }

    private static uint Number(MasterFileToken token, uint maximum)
    {
        Require(!token.Quoted && token.Text.Length != 0);
        ulong number = 0;
        foreach (var character in token.Text)
        {
            Require(character is >= '0' and <= '9');
            number = number * 10 + (uint)(character - '0');
            Require(number <= maximum);
        }
        return (uint)number;
    }

    private static byte[] Hex(IEnumerable<MasterFileToken> tokens)
    {
        using var output = new MemoryStream();
        foreach (var token in tokens)
        {
            Require(!token.Quoted && token.Text.Length != 0 && token.Text.Length % 2 == 0 && token.Text.All(Uri.IsHexDigit));
            Require(output.Length + token.Text.Length / 2 <= ushort.MaxValue);
            output.Write(Convert.FromHexString(token.Text));
        }
        return output.ToArray();
    }

    private static byte[] Octets(string text)
    {
        List<byte> result = [];
        for (var position = 0; position < text.Length; position++)
            result.Add(Octet(text, ref position));
        return [.. result];
    }

    private static byte Octet(string text, ref int position)
    {
        var character = text[position];
        if (character != '\\')
            return (byte)character;
        Require(++position < text.Length);
        character = text[position];
        if (character is not (>= '0' and <= '9'))
            return (byte)character;
        Require(position + 3 <= text.Length);
        var value = Number(new MasterFileToken(text.Substring(position, 3), false), byte.MaxValue);
        position += 2;
        return (byte)value;
    }

    private static void Write16(Stream output, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        output.Write(bytes);
    }

    private static void Write32(Stream output, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        output.Write(bytes);
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Invalid master-file record field.");
    }
}
