using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public static partial class UpstreamMessageCodec
{
    public static byte[] EncodeQuery(ushort id, DnsQuestion question)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (question.Name is null || question.Class != 1 || question.Type is 0 or 41 or (>= 249 and <= 255))
            throw new ArgumentException("Only ordinary Internet-class questions can be sent upstream.", nameof(question));
        var name = question.Name.ToWire();
        var result = new byte[12 + name.Length + 4 + 11];
        Write16(result, 0, id);
        Write16(result, 4, 1);
        Write16(result, 10, 1);
        name.CopyTo(result, 12);
        Write16(result, 12 + name.Length, question.Type);
        Write16(result, 14 + name.Length, question.Class);
        var opt = 16 + name.Length;
        Write16(result, opt + 1, 41);
        Write16(result, opt + 3, 1232);
        // RD, CD, AD and DO are all clear: this profile never requests upstream recursion.
        return result;
    }

    public static UpstreamResponse DecodeResponse(ReadOnlySpan<byte> message, ushort id, DnsQuestion question)
    {
        ArgumentNullException.ThrowIfNull(question);
        Require(message.Length is >= 12 and <= 65535);
        var flags = Read16(message, 2);
        Require(Read16(message, 0) == id && (flags & 0xf840) == 0x8000 && Read16(message, 4) == 1);
        var offset = 12;
        HashSet<int> boundaries = [];
        var name = ReadName(message, ref offset, boundaries);
        Require(offset + 4 <= message.Length && DnsName.FromWire(name).Equals(question.Name)
            && Read16(message, offset) == question.Type && Read16(message, offset + 2) == question.Class);
        offset += 4;
        if ((flags & 0x0200) != 0)
            return new UpstreamResponse(new DnsAnswer((byte)(flags & 15), (flags & 0x0400) != 0, [], [], []), true);
        var answerCount = Read16(message, 6);
        var authorityCount = Read16(message, 8);
        var additionalCount = Read16(message, 10);
        Require(answerCount + authorityCount + additionalCount <= 512);
        byte extendedCode = 0;
        var optSeen = false;
        var answers = ReadSection(message, ref offset, answerCount, boundaries, false, ref optSeen, ref extendedCode);
        var authority = ReadSection(message, ref offset, authorityCount, boundaries, false, ref optSeen, ref extendedCode);
        var additional = ReadSection(message, ref offset, additionalCount, boundaries, true, ref optSeen, ref extendedCode);
        Require(offset == message.Length && extendedCode <= 15);
        return new UpstreamResponse(new DnsAnswer((byte)((extendedCode << 4) | (flags & 15)), (flags & 0x0400) != 0, answers, authority, additional), false);
    }

    private static List<DnsRecord> ReadSection(ReadOnlySpan<byte> message, ref int offset, int count, HashSet<int> boundaries,
        bool allowOpt, ref bool optSeen, ref byte extendedCode)
    {
        List<DnsRecord> records = [];
        for (var index = 0; index < count; index++)
        {
            var owner = ReadName(message, ref offset, boundaries);
            Require(offset + 10 <= message.Length);
            var type = Read16(message, offset);
            var recordClass = Read16(message, offset + 2);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(message[(offset + 4)..]);
            var length = Read16(message, offset + 8);
            offset += 10;
            Require(length <= message.Length - offset);
            var end = offset + length;
            if (type == 41)
            {
                Require(allowOpt && !optSeen && owner.Length == 1 && ((ttl >> 16) & 255) == 0);
                optSeen = true;
                extendedCode = (byte)(ttl >> 24);
                while (offset < end)
                {
                    Require(end - offset >= 4);
                    var optionBytes = Read16(message, offset + 2);
                    offset += 4;
                    Require(optionBytes <= end - offset);
                    offset += optionBytes;
                }
            }
            else
            {
                Require(recordClass == 1 && type != 0 && type is not (>= 249 and <= 255));
                var data = ExpandData(message, ref offset, end, type, boundaries);
                // RFC 2181 section 8: an incoming TTL with its high bit set means zero.
                records.Add(new DnsRecord(owner, type, ttl > int.MaxValue ? 0 : ttl, data));
            }
            Require(offset == end);
        }
        return records;
    }

    private static byte[] ExpandData(ReadOnlySpan<byte> message, ref int offset, int end, ushort type, HashSet<int> boundaries)
    {
        var start = offset;
        var (prefix, names) = NameLayout(message[start..end], type);
        if (names == 0)
        {
            offset = end;
            return message[start..end].ToArray();
        }
        Require(prefix <= end - offset);
        List<byte> expanded = [.. message.Slice(offset, prefix)];
        offset += prefix;
        for (var index = 0; index < names; index++)
        {
            var value = ReadName(message, ref offset, boundaries);
            Require(offset <= end);
            // Modern DNAME/RRSIG/NSEC explicitly forbid name compression.
            if (type is 38 or 39 or 46 or 47 or 64 or 65)
                Require(message.Slice(start + prefix, offset - start - prefix).SequenceEqual(value));
            expanded.AddRange(value);
        }
        if (type == 6)
            Require(end - offset == 20);
        else if (type is not (24 or 30 or 46 or 47 or 64 or 65))
            Require(offset == end);
        expanded.AddRange(message[offset..end].ToArray());
        Require(expanded.Count <= ushort.MaxValue);
        offset = end;
        return [.. expanded];
    }

    private static (int Prefix, int Names) NameLayout(ReadOnlySpan<byte> data, ushort type)
    {
        if (type == 35)
            return (NaptrPrefix(data), 1);
        if (type == 38)
        {
            Require(!data.IsEmpty && data[0] <= 128);
            var prefix = 1 + (128 - data[0] + 7) / 8;
            var names = data[0] == 0 ? 0 : 1;
            Require(prefix <= data.Length && (names != 0 || prefix == data.Length));
            return (prefix, names);
        }
        return (type switch { 15 or 18 or 21 or 26 or 64 or 65 => 2, 33 => 6, 24 or 46 => 18, _ => 0 },
            type switch { 6 or 14 or 17 or 26 => 2, 2 or 3 or 4 or 5 or 7 or 8 or 9 or 12 or 15 or 18 or 21 or 24 or 30 or 33 or 39 or 46 or 47 or 64 or 65 => 1, _ => 0 });
    }

    private static int NaptrPrefix(ReadOnlySpan<byte> data)
    {
        Require(data.Length >= 4);
        var offset = 4;
        for (var field = 0; field < 3; field++)
        {
            Require(offset < data.Length);
            var length = data[offset++];
            Require(length <= data.Length - offset);
            offset += length;
        }
        return offset;
    }

    private static ushort Read16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
    private static byte[] ReadName(ReadOnlySpan<byte> message, ref int offset, HashSet<int> boundaries)
    {
        var cursor = offset;
        var consumed = -1;
        var steps = 0;
        List<byte> result = [];
        while (true)
        {
            Require(cursor < message.Length && ++steps <= 256);
            var start = cursor;
            var length = message[cursor++];
            if ((length & 0xc0) == 0xc0)
            {
                Require(cursor < message.Length);
                var target = ((length & 0x3f) << 8) | message[cursor++];
                Require(target < start && boundaries.Contains(target));
                boundaries.Add(start);
                if (consumed < 0) consumed = cursor;
                cursor = target;
                continue;
            }
            Require(length <= 63 && length <= message.Length - cursor);
            boundaries.Add(start);
            result.Add(length);
            for (var octet = 0; octet < length; octet++) result.Add(message[cursor++]);
            Require(result.Count <= 255);
            if (length == 0) break;
        }
        offset = consumed < 0 ? cursor : consumed;
        return [.. result];
    }
    private static void Write16(Span<byte> bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(bytes[offset..], value);
    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Malformed or uncorrelated upstream DNS response.");
    }
}
