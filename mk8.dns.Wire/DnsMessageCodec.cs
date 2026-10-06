using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public static class DnsMessageCodec
{
    public const int MaximumMessageBytes = 65_535;
    public const ushort MaximumUdpPayloadSize = 1232;

    public static DnsQuery DecodeQuery(ReadOnlySpan<byte> message)
    {
        Require(message.Length is >= 12 and <= MaximumMessageBytes);
        var flags = Read16(message, 2);
        Require((flags & 0x8040) == 0);
        if ((flags & 0x7800) != 0)
            throw new NotSupportedException("Only standard DNS queries are implemented.");
        Require(Read16(message, 4) == 1 && Read16(message, 6) == 0 && Read16(message, 8) == 0);
        var additional = Read16(message, 10);
        Require(additional <= 1);
        var offset = 12;
        HashSet<int> nameBoundaries = [];
        var name = ReadName(message, ref offset, nameBoundaries);
        Require(offset + 4 <= message.Length);
        var question = new DnsQuestion(DnsName.FromWire(name), Read16(message, offset), Read16(message, offset + 2));
        offset += 4;
        ushort udpSize = 512;
        byte version = 0;
        var dnssecOk = false;
        if (additional != 0)
        {
            var owner = ReadName(message, ref offset, nameBoundaries);
            Require(owner.Length == 1 && offset + 10 <= message.Length && Read16(message, offset) == 41);
            udpSize = Math.Clamp(Read16(message, offset + 2), (ushort)512, MaximumUdpPayloadSize);
            Require(message[offset + 4] == 0);
            version = message[offset + 5];
            dnssecOk = (Read16(message, offset + 6) & 0x8000) != 0;
            var length = Read16(message, offset + 8);
            offset += 10;
            Require(length == message.Length - offset);
            var end = offset + length;
            while (offset < end)
            {
                Require(offset + 4 <= end);
                var optionLength = Read16(message, offset + 2);
                offset += 4;
                Require(optionLength <= end - offset);
                offset += optionLength;
            }
        }
        Require(offset == message.Length);
        return new DnsQuery(Read16(message, 0), flags, question, name, udpSize, additional != 0, version, dnssecOk);
    }

    public static byte[] EncodeResponse(DnsQuery query, DnsAnswer answer, bool tcp)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(answer);
        if (query.EdnsVersion != 0)
            answer = new DnsAnswer(16, false, [], [], []);
        var limit = tcp ? MaximumMessageBytes : query.UdpPayloadSize;
        var buffer = new byte[limit];
        var offset = 12;
        var originalName = query.GetQuestionNameWire();
        originalName.CopyTo(buffer, offset);
        offset += originalName.Length;
        Write16(buffer, ref offset, query.Question.Type);
        Write16(buffer, ref offset, query.Question.Class);
        var usable = limit - (query.HasEdns ? 11 : 0);
        var truncated = false;
        var answers = WriteSection(answer.Answers, buffer, ref offset, usable, query, ref truncated);
        var authority = WriteSection(answer.Authority, buffer, ref offset, usable, query, ref truncated);
        var additional = WriteSection(answer.Additional, buffer, ref offset, usable, query, ref truncated);
        if (query.HasEdns)
        {
            buffer[offset++] = 0;
            Write16(buffer, ref offset, 41);
            Write16(buffer, ref offset, MaximumUdpPayloadSize);
            var optTtl = (uint)(answer.ResponseCode >> 4) << 24;
            if (query.DnssecOk)
                optTtl |= 0x8000;
            Write32(buffer, ref offset, optTtl);
            Write16(buffer, ref offset, 0);
            additional++;
        }
        var header = 0;
        Write16(buffer, ref header, query.Id);
        var flags = 0x8000 | (query.Flags & 0x0110) | (answer.ResponseCode & 15);
        if (answer.Authoritative)
            flags |= 0x0400;
        if (truncated)
            flags |= 0x0200;
        Write16(buffer, ref header, (ushort)flags);
        Write16(buffer, ref header, 1);
        Write16(buffer, ref header, answers);
        Write16(buffer, ref header, authority);
        Write16(buffer, ref header, additional);
        return buffer[..offset];
    }

    public static byte[] EncodeError(ReadOnlySpan<byte> request, byte responseCode)
    {
        // Do not reflect short packets or unsolicited responses.
        if (request.Length < 12 || (Read16(request, 2) & 0x8000) != 0)
            return [];
        var response = new byte[12];
        var offset = 0;
        Write16(response, ref offset, Read16(request, 0));
        Write16(response, ref offset, (ushort)(0x8000 | (Read16(request, 2) & 0x7910) | (responseCode & 15)));
        return response;
    }

    private static ushort WriteSection(IReadOnlyList<DnsRecord> records, byte[] buffer, ref int offset, int limit, DnsQuery query, ref bool truncated)
    {
        if (truncated)
            return 0;
        ushort count = 0;
        foreach (var rrset in records.GroupBy(record => (record.Owner, record.Type)))
        {
            var values = rrset.Select(record => (Record: record, Data: record.GetData())).ToArray();
            var owner = rrset.Key.Owner.Equals(query.Question.Name) ? new byte[] { 0xc0, 0x0c } : values[0].Record.GetOwnerWire();
            var needed = values.Sum(item => owner.Length + 10 + item.Data.Length);
            if (needed > limit - offset || values.Length > ushort.MaxValue - count)
            {
                truncated = true;
                break;
            }
            foreach (var item in values)
            {
                owner.CopyTo(buffer, offset);
                offset += owner.Length;
                Write16(buffer, ref offset, item.Record.Type);
                Write16(buffer, ref offset, 1);
                Write32(buffer, ref offset, item.Record.Ttl);
                Write16(buffer, ref offset, (ushort)item.Data.Length);
                item.Data.CopyTo(buffer, offset);
                offset += item.Data.Length;
                count++;
            }
        }
        return count;
    }

    private static byte[] ReadName(ReadOnlySpan<byte> message, ref int offset, HashSet<int> boundaries)
    {
        var cursor = offset;
        var consumed = -1;
        var hops = 0;
        List<byte> result = [];
        while (true)
        {
            Require(cursor < message.Length && ++hops <= 128);
            var start = cursor;
            var length = message[cursor++];
            if ((length & 0xc0) == 0xc0)
            {
                Require(cursor < message.Length);
                var target = ((length & 0x3f) << 8) | message[cursor++];
                Require(target < start && boundaries.Contains(target));
                if (consumed < 0)
                    consumed = cursor;
                cursor = target;
                continue;
            }
            Require(length <= 63 && length <= message.Length - cursor);
            boundaries.Add(start);
            result.Add(length);
            for (var index = 0; index < length; index++)
                result.Add(message[cursor++]);
            Require(result.Count <= 255);
            if (length == 0)
                break;
        }
        offset = consumed < 0 ? cursor : consumed;
        return [.. result];
    }

    private static ushort Read16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
    private static void Write16(Span<byte> bytes, ref int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(bytes[offset..], value);
        offset += 2;
    }
    private static void Write32(Span<byte> bytes, ref int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(bytes[offset..], value);
        offset += 4;
    }
    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Malformed DNS query.");
    }
}
