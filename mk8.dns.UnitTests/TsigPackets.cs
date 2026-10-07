using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Mk8.Dns.UnitTests;

internal static class TsigPackets
{
    internal static readonly byte[] Secret = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();

    internal static byte[] Sign(byte[] message, ulong time = 1559731985, ushort fudge = 300, int macLength = 32, string key = "query-key.", string algorithm = "hmac-sha256.", byte[]? secret = null, byte[]? other = null, ushort? originalId = null)
    {
        var id = originalId ?? BinaryPrimitives.ReadUInt16BigEndian(message);
        var data = other ?? [];
        var mac = HMACSHA256.HashData(secret ?? Secret, Input(message, key, algorithm, time, fudge, 0, data, [], id))[..macLength];
        return Append(message, key, algorithm, time, fudge, mac, id, 0, data);
    }

    internal static byte[] Append(byte[] message, string key, string algorithm, ulong time, ushort fudge, byte[] mac, ushort id, ushort error, byte[] other)
    {
        using var record = new MemoryStream();
        record.Write(Name(algorithm));
        Time(record, time); Number(record, fudge); Number(record, (ushort)mac.Length); record.Write(mac);
        Number(record, id); Number(record, error); Number(record, (ushort)other.Length); record.Write(other);
        using var output = new MemoryStream();
        var header = (byte[])message.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(10), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(10)) + 1));
        output.Write(header); output.Write(Name(key)); Number(output, 250); Number(output, 255); output.Write(new byte[4]); Number(output, (ushort)record.Length); record.WriteTo(output);
        return output.ToArray();
    }

    internal static byte[] Input(byte[] message, string key, string algorithm, ulong time, ushort fudge, ushort error, byte[] other, byte[] prior, ushort id)
    {
        using var output = new MemoryStream();
        if (prior.Length != 0)
        {
            Number(output, (ushort)prior.Length); output.Write(prior);
        }
        var body = (byte[])message.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(body, id);
        output.Write(body); output.Write(CanonicalName(key)); Number(output, 255); output.Write(new byte[4]); output.Write(CanonicalName(algorithm));
        Time(output, time); Number(output, fudge); Number(output, error); Number(output, (ushort)other.Length); output.Write(other);
        return output.ToArray();
    }

    internal static TsigReply Parse(byte[] message)
    {
        var offset = 12;
        for (var index = 0; index < BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(4)); index++)
        {
            _ = ReadName(message, ref offset); offset += 4;
        }
        var count = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(6)) + BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(8)) + BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(10));
        for (var index = 0; index < count; index++)
        {
            var start = offset;
            var owner = ReadName(message, ref offset);
            var type = Number(message, ref offset); _ = Number(message, ref offset); offset += 4;
            var length = Number(message, ref offset); var end = offset + length;
            if (type == 250)
            {
                var algorithm = ReadName(message, ref offset);
                var time = ((ulong)Number(message, ref offset) << 32) | BinaryPrimitives.ReadUInt32BigEndian(message.AsSpan(offset)); offset += 4;
                var fudge = Number(message, ref offset); var size = Number(message, ref offset);
                var mac = message.AsSpan(offset, size).ToArray(); offset += size;
                var id = Number(message, ref offset); var error = Number(message, ref offset); var otherSize = Number(message, ref offset);
                var other = message.AsSpan(offset, otherSize).ToArray(); offset += otherSize;
                if (offset != end || end != message.Length || index != count - 1)
                    throw new InvalidDataException("Invalid independent TSIG response inventory.");
                var unsigned = message[..start];
                BinaryPrimitives.WriteUInt16BigEndian(unsigned.AsSpan(10), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(10)) - 1));
                return new TsigReply(unsigned, owner, algorithm, time, fudge, mac, id, error, other, start);
            }
            offset = end;
        }
        throw new InvalidDataException("Missing TSIG in independent response oracle.");
    }

    internal static byte[] ExpectedMac(TsigReply reply, byte[] request, byte[]? secret = null) => HMACSHA256.HashData(secret ?? Secret,
        Input(reply.Message, reply.Key, reply.Algorithm, reply.Time, reply.Fudge, reply.Error, reply.Other, Parse(request).Mac, reply.Id));

    private static byte[] Name(string value) => string.Equals(value, ".", StringComparison.Ordinal) ? [0]
        : value.TrimEnd('.').Split('.').SelectMany(label => new[] { (byte)label.Length }.Concat(Encoding.ASCII.GetBytes(label))).Append((byte)0).ToArray();

    private static byte[] CanonicalName(string value)
    {
        var bytes = Name(value);
        for (var index = 0; index < bytes.Length; index++)
            if (bytes[index] is >= (byte)'A' and <= (byte)'Z')
                bytes[index] += 32;
        return bytes;
    }

    private static string ReadName(byte[] message, ref int offset)
    {
        List<string> labels = [];
        var cursor = offset; var consumed = -1;
        while (true)
        {
            var length = message[cursor++];
            if ((length & 0xc0) == 0xc0)
            {
                var target = ((length & 0x3f) << 8) | message[cursor++]; consumed = consumed < 0 ? cursor : consumed; cursor = target; continue;
            }
            if (length == 0) break;
            labels.Add(Encoding.ASCII.GetString(message, cursor, length)); cursor += length;
        }
        offset = consumed < 0 ? cursor : consumed;
        return string.Join('.', labels) + ".";
    }

    private static void Number(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); stream.Write(bytes);
    }
    private static void Time(Stream stream, ulong time)
    {
        Span<byte> bytes = stackalloc byte[6]; BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)(time >> 32)); BinaryPrimitives.WriteUInt32BigEndian(bytes[2..], (uint)time); stream.Write(bytes);
    }
    private static ushort Number(byte[] message, ref int offset)
    {
        var value = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(offset)); offset += 2; return value;
    }
}
