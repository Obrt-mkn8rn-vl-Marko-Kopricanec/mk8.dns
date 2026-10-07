using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public static class TsigMessageCodec
{
    public static TsigRequest? DecodeRequest(ReadOnlySpan<byte> message)
    {
        Require(message.Length is >= 12 and <= ushort.MaxValue);
        var questions = Read16(message, 4);
        var answers = Read16(message, 6);
        var authority = Read16(message, 8);
        var additional = Read16(message, 10);
        if (answers == 0 && authority == 0 && additional == 0)
            return null;
        var offset = 12;
        HashSet<int> boundaries = [];
        for (var index = 0; index < questions; index++)
        {
            _ = DnsMessageCodec.ReadName(message, ref offset, boundaries);
            Require(offset + 4 <= message.Length);
            offset += 4;
        }
        var count = (int)answers + authority + additional;
        TsigRequest? result = null;
        for (var index = 0; index < count; index++)
        {
            var start = offset;
            var owner = DnsMessageCodec.ReadName(message, ref offset, boundaries);
            Require(offset + 10 <= message.Length);
            var type = Read16(message, offset);
            var cls = Read16(message, offset + 2);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(message[(offset + 4)..]);
            var length = Read16(message, offset + 8);
            offset += 10;
            Require(length <= message.Length - offset);
            var end = offset + length;
            if (type == 250)
            {
                Require(index >= answers + authority && index == count - 1 && result is null && cls == 255 && ttl == 0);
                result = ReadSignature(message[..end], offset, start, owner, additional);
            }
            offset = end;
        }
        Require(offset == message.Length);
        return result;
    }

    private static TsigRequest ReadSignature(ReadOnlySpan<byte> message, int offset, int start, byte[] owner, ushort additional)
    {
        var algorithm = ReadUncompressedName(message, ref offset);
        Require(offset + 10 <= message.Length);
        var time = ReadTime(message, offset);
        var fudge = Read16(message, offset + 6);
        var size = Read16(message, offset + 8);
        offset += 10;
        Require(size <= message.Length - offset);
        var mac = message.Slice(offset, size).ToArray();
        offset += size;
        Require(offset + 6 <= message.Length);
        var id = Read16(message, offset);
        var error = Read16(message, offset + 2);
        var otherLength = Read16(message, offset + 4);
        offset += 6;
        Require(error == 0 && otherLength == message.Length - offset);
        var unsigned = message[..start].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(unsigned.AsSpan(10), (ushort)(additional - 1));
        return new TsigRequest(unsigned, DnsName.FromWire(owner), DnsName.FromWire(algorithm), time, fudge, mac, id, error, message.Slice(offset, otherLength).ToArray());
    }

    public static int GetRecordSize(TsigRequest request, int macBytes, int otherBytes)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (macBytes is < 0 or > ushort.MaxValue || otherBytes is < 0 or > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(macBytes));
        return request.KeyName.ToWire().Length + 10 + request.Algorithm.ToWire().Length + 16 + macBytes + otherBytes;
    }

    public static byte[] CreateMacInput(ReadOnlySpan<byte> message, TsigRequest request, ReadOnlySpan<byte> requestMac, ulong timeSigned, ushort fudge, ushort error, ReadOnlySpan<byte> otherData)
    {
        ArgumentNullException.ThrowIfNull(request);
        CheckEncoding(message, timeSigned, requestMac, otherData);
        var name = request.KeyName.ToWire();
        var algorithm = request.Algorithm.ToWire();
        var prefix = requestMac.IsEmpty ? 0 : 2 + requestMac.Length;
        var output = new byte[prefix + message.Length + name.Length + 6 + algorithm.Length + 12 + otherData.Length];
        var offset = 0;
        if (prefix != 0)
        {
            Write16(output, ref offset, (ushort)requestMac.Length);
            Copy(requestMac, output, ref offset);
        }
        Copy(message, output, ref offset);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(prefix), request.OriginalId);
        Copy(name, output, ref offset);
        Write16(output, ref offset, 255);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), 0);
        offset += 4;
        Copy(algorithm, output, ref offset);
        WriteTime(output, ref offset, timeSigned);
        Write16(output, ref offset, fudge);
        Write16(output, ref offset, error);
        Write16(output, ref offset, (ushort)otherData.Length);
        Copy(otherData, output, ref offset);
        return output;
    }

    public static byte[] AppendRecord(ReadOnlySpan<byte> message, TsigRequest request, ulong timeSigned, ushort fudge, ushort error, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> otherData)
    {
        ArgumentNullException.ThrowIfNull(request);
        CheckEncoding(message, timeSigned, mac, otherData);
        var name = request.KeyName.ToWire();
        var algorithm = request.Algorithm.ToWire();
        var size = GetRecordSize(request, mac.Length, otherData.Length);
        if (message.Length + size > ushort.MaxValue || Read16(message, 10) == ushort.MaxValue || size - name.Length - 10 > ushort.MaxValue)
            throw new ArgumentException("TSIG exceeds the DNS response bound.", nameof(message));
        var output = new byte[message.Length + size];
        message.CopyTo(output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(10), (ushort)(Read16(message, 10) + 1));
        var offset = message.Length;
        Copy(name, output, ref offset);
        Write16(output, ref offset, 250);
        Write16(output, ref offset, 255);
        offset += 4;
        Write16(output, ref offset, (ushort)(size - name.Length - 10));
        Copy(algorithm, output, ref offset);
        WriteTime(output, ref offset, timeSigned);
        Write16(output, ref offset, fudge);
        Write16(output, ref offset, (ushort)mac.Length);
        Copy(mac, output, ref offset);
        Write16(output, ref offset, request.OriginalId);
        Write16(output, ref offset, error);
        Write16(output, ref offset, (ushort)otherData.Length);
        Copy(otherData, output, ref offset);
        return output;
    }

    private static byte[] ReadUncompressedName(ReadOnlySpan<byte> message, ref int offset)
    {
        var start = offset;
        while (true)
        {
            Require(offset < message.Length);
            var size = message[offset++];
            Require(size <= 63 && size <= message.Length - offset);
            offset += size;
            Require(offset - start <= 255);
            if (size == 0)
                return message[start..offset].ToArray();
        }
    }

    private static void CheckEncoding(ReadOnlySpan<byte> message, ulong time, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> other)
    {
        if (message.Length is < 12 or > ushort.MaxValue || time > 0xffff_ffff_ffff || mac.Length > ushort.MaxValue || other.Length > ushort.MaxValue)
            throw new ArgumentException("Invalid TSIG encoding bounds.", nameof(message));
    }

    private static ulong ReadTime(ReadOnlySpan<byte> bytes, int offset) => ((ulong)Read16(bytes, offset) << 32) | BinaryPrimitives.ReadUInt32BigEndian(bytes[(offset + 2)..]);
    private static ushort Read16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
    private static void WriteTime(Span<byte> bytes, ref int offset, ulong time)
    {
        Write16(bytes, ref offset, (ushort)(time >> 32));
        BinaryPrimitives.WriteUInt32BigEndian(bytes[offset..], (uint)time);
        offset += 4;
    }
    private static void Write16(Span<byte> bytes, ref int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(bytes[offset..], value);
        offset += 2;
    }
    private static void Copy(ReadOnlySpan<byte> source, Span<byte> output, ref int offset)
    {
        source.CopyTo(output[offset..]);
        offset += source.Length;
    }
    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Malformed TSIG message.");
    }
}
