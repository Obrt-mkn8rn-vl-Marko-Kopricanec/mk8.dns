using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Mk8.Dns.Wire;

internal static class MasterFileServiceBinding
{
    internal static byte[] Encode(IReadOnlyList<MasterFileToken> fields, byte[] origin)
    {
        Require(fields.Count >= 2);
        using var output = new MemoryStream();
        Write16(output, (ushort)MasterFileData.Number(fields[0], ushort.MaxValue));
        output.Write(MasterFileData.Name(fields[1], origin));
        SortedDictionary<ushort, byte[]> parameters = [];
        var size = output.Length;
        foreach (var field in fields.Skip(2))
        {
            Require(!field.Quoted && !field.Text.Contains('\r', StringComparison.Ordinal) && !field.Text.Contains('\n', StringComparison.Ordinal));
            var equals = field.Text.IndexOf('=', StringComparison.Ordinal);
            var name = equals < 0 ? field.Text : field.Text[..equals];
            var key = Key(name);
            var text = equals < 0 ? string.Empty : field.Text[(equals + 1)..];
            // RFC 9460 unknown-key notation supplies raw wire octets even for a known key.
            var value = name.StartsWith("key", StringComparison.Ordinal) ? MasterFileData.Octets(text) : Parameter(key, text);
            Require(parameters.TryAdd(key, value));
            size += value.Length + 4;
            Require(size <= ushort.MaxValue);
        }
        foreach (var (key, value) in parameters)
        {
            Write16(output, key);
            Write16(output, (ushort)value.Length);
            output.Write(value);
        }
        return output.ToArray();
    }

    private static ushort Key(string name)
    {
        Require(name.Length is >= 1 and <= 63 && name.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-'));
        return name switch
        {
            "mandatory" => 0,
            "alpn" => 1,
            "no-default-alpn" => 2,
            "port" => 3,
            "ipv4hint" => 4,
            "ech" => 5,
            "ipv6hint" => 6,
            _ => NumericKey(name),
        };
    }

    private static ushort NumericKey(string name)
    {
        Require(name.StartsWith("key", StringComparison.Ordinal) && name.Length > 3);
        var number = name[3..];
        Require(number.Length == 1 || number[0] != '0');
        return (ushort)MasterFileData.Number(new MasterFileToken(number, false), ushort.MaxValue - 1U);
    }

    private static byte[] Parameter(ushort key, string text)
    {
        if (key != 1)
            Require(!text.Contains('\\', StringComparison.Ordinal));
        return key switch
        {
            0 => Mandatory(text),
            1 => Alpn(MasterFileData.Octets(text)),
            2 when text.Length == 0 => [],
            3 => Port(text),
            4 => Hints(text, AddressFamily.InterNetwork),
            5 => Ech(text),
            6 => Hints(text, AddressFamily.InterNetworkV6),
            _ => throw new FormatException("Invalid typed service parameter."),
        };
    }

    private static byte[] Mandatory(string text)
    {
        var keys = text.Split(',').Select(Key).Order().ToArray();
        Require(keys.Length != 0 && keys[0] != 0 && keys.Distinct().Count() == keys.Length);
        using var output = new MemoryStream();
        foreach (var key in keys)
            Write16(output, key);
        return output.ToArray();
    }

    private static byte[] Port(string text)
    {
        var port = (ushort)MasterFileData.Number(new MasterFileToken(text, false), ushort.MaxValue);
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, port);
        return result;
    }

    private static byte[] Hints(string text, AddressFamily family)
    {
        using var output = new MemoryStream();
        foreach (var item in text.Split(','))
        {
            Require(item.Length != 0 && !item.Contains('%', StringComparison.Ordinal) && !item.Any(char.IsWhiteSpace));
            if (family == AddressFamily.InterNetwork)
            {
                var octets = item.Split('.');
                Require(octets.Length == 4);
                foreach (var octet in octets)
                    output.WriteByte((byte)MasterFileData.Number(new MasterFileToken(octet, false), byte.MaxValue));
            }
            else
            {
                Require(item.All(character => char.IsAsciiHexDigit(character) || character is ':' or '.'));
                Require(IPAddress.TryParse(item, out var address) && address.AddressFamily == family);
                output.Write(address!.GetAddressBytes());
            }
        }
        return output.ToArray();
    }

    private static byte[] Ech(string text)
    {
        Require(text.Length != 0 && text.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/' or '='));
        var data = Convert.FromBase64String(text);
        // Public ECHConfigList bytes are conveyed opaquely; TLS capabilities/keys stay external.
        Require(string.Equals(Convert.ToBase64String(data), text, StringComparison.Ordinal));
        return data;
    }

    private static byte[] Alpn(byte[] text)
    {
        using var output = new MemoryStream();
        List<byte> item = [];
        for (var position = 0; position < text.Length; position++)
        {
            var octet = text[position];
            if (octet == ',')
            {
                WriteAlpn(output, item);
                item.Clear();
            }
            else
            {
                if (octet == '\\')
                {
                    Require(++position < text.Length && text[position] is (byte)',' or (byte)'\\');
                    octet = text[position];
                }
                item.Add(octet);
                Require(item.Count <= byte.MaxValue);
            }
        }
        WriteAlpn(output, item);
        return output.ToArray();
    }

    private static void WriteAlpn(Stream output, List<byte> item)
    {
        Require(item.Count != 0);
        output.WriteByte((byte)item.Count);
        output.Write(item.ToArray());
    }

    private static void Write16(Stream output, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        output.Write(bytes);
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Invalid master-file service binding.");
    }
}
