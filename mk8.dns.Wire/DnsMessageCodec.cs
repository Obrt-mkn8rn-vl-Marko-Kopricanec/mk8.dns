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
        var questions = Read16(message, 4);
        Require(questions <= 1 && Read16(message, 6) == 0 && Read16(message, 8) == 0);
        var additional = Read16(message, 10);
        Require(additional <= 1);
        var offset = 12;
        HashSet<int> nameBoundaries = [];
        byte[] name = [];
        DnsQuestion? question = null;
        if (questions != 0)
        {
            name = ReadName(message, ref offset, nameBoundaries);
            Require(offset + 4 <= message.Length);
            question = new DnsQuestion(DnsName.FromWire(name), Read16(message, offset), Read16(message, offset + 2));
            offset += 4;
        }
        ushort udpSize = 512;
        byte version = 0;
        var dnssecOk = false;
        byte[]? cookie = null;
        if (additional != 0)
            (udpSize, version, dnssecOk, cookie) = ReadEdns(message, ref offset, nameBoundaries);
        Require(offset == message.Length);
        Require(question is not null || cookie is not null);
        return new DnsQuery(Read16(message, 0), flags, question, name, udpSize, additional != 0, version, dnssecOk, cookie);
    }

    private static (ushort Size, byte Version, bool DnssecOk, byte[]? Cookie) ReadEdns(ReadOnlySpan<byte> message, ref int offset, HashSet<int> boundaries)
    {
        var owner = ReadName(message, ref offset, boundaries);
        Require(owner.Length == 1 && offset + 10 <= message.Length && Read16(message, offset) == 41);
        var size = Math.Clamp(Read16(message, offset + 2), (ushort)512, MaximumUdpPayloadSize);
        Require(message[offset + 4] == 0);
        var version = message[offset + 5];
        var dnssecOk = (Read16(message, offset + 6) & 0x8000) != 0;
        var length = Read16(message, offset + 8);
        offset += 10;
        Require(length == message.Length - offset);
        byte[]? cookie = null;
        while (offset < message.Length)
        {
            Require(offset + 4 <= message.Length);
            var code = Read16(message, offset);
            var optionLength = Read16(message, offset + 2);
            offset += 4;
            Require(optionLength <= message.Length - offset);
            if (code == 10 && cookie is null)
                cookie = message.Slice(offset, optionLength).ToArray();
            offset += optionLength;
        }
        return (size, version, dnssecOk, cookie);
    }

    public static byte[] EncodeResponse(DnsQuery query, DnsAnswer answer, bool tcp) => EncodeResponse(query, answer, tcp, [], MaximumUdpPayloadSize);

    public static byte[] EncodeResponse(DnsQuery query, DnsAnswer answer, bool tcp, ReadOnlySpan<byte> cookie, ushort udpLimit)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(answer);
        if (udpLimit is < 512 or > MaximumUdpPayloadSize || cookie.Length != 0 && (cookie.Length != 24 || !query.HasEdns
            || query.GetCookieWire() is not { Length: >= 8 } requestCookie || !cookie[..8].SequenceEqual(requestCookie.AsSpan(0, 8))))
            throw new ArgumentException("Invalid response cookie or UDP policy.", nameof(cookie));
        if (query.EdnsVersion != 0)
        {
            answer = new DnsAnswer(16, false, [], [], []);
            cookie = [];
        }
        if (query.Question is null && (answer.Answers.Count != 0 || answer.Authority.Count != 0 || answer.Additional.Count != 0))
            throw new ArgumentException("Cookie prefetch cannot contain DNS answer data.", nameof(answer));
        var limit = tcp ? MaximumMessageBytes : Math.Min(query.UdpPayloadSize, udpLimit);
        var buffer = new byte[limit];
        var offset = 12;
        var originalName = query.GetQuestionNameWire();
        originalName.CopyTo(buffer, offset);
        offset += originalName.Length;
        if (query.Question is { } question)
        {
            Write16(buffer, ref offset, question.Type);
            Write16(buffer, ref offset, question.Class);
        }
        var usable = limit - (query.HasEdns ? 11 + (cookie.Length == 0 ? 0 : 4 + cookie.Length) : 0);
        var truncated = false;
        var answers = WriteSection(answer.Answers, buffer, ref offset, usable, query, ref truncated);
        var authority = WriteSection(answer.Authority, buffer, ref offset, usable, query, ref truncated);
        var additional = WriteSection(answer.Additional, buffer, ref offset, usable, query, ref truncated);
        if (query.HasEdns)
        {
            WriteOpt(buffer, ref offset, query, answer.ResponseCode, cookie);
            additional++;
        }
        WriteHeader(buffer, query, answer, truncated, answers, authority, additional);
        return buffer[..offset];
    }

    private static void WriteOpt(Span<byte> buffer, ref int offset, DnsQuery query, byte code, ReadOnlySpan<byte> cookie)
    {
        buffer[offset++] = 0;
        Write16(buffer, ref offset, 41);
        Write16(buffer, ref offset, MaximumUdpPayloadSize);
        var ttl = (uint)(code >> 4) << 24;
        if (query.DnssecOk)
            ttl |= 0x8000;
        Write32(buffer, ref offset, ttl);
        Write16(buffer, ref offset, (ushort)(cookie.Length == 0 ? 0 : 4 + cookie.Length));
        if (cookie.Length != 0)
        {
            Write16(buffer, ref offset, 10);
            Write16(buffer, ref offset, (ushort)cookie.Length);
            cookie.CopyTo(buffer[offset..]);
            offset += cookie.Length;
        }
    }

    private static void WriteHeader(Span<byte> buffer, DnsQuery query, DnsAnswer answer, bool truncated, ushort answers, ushort authority, ushort additional)
    {
        var header = 0;
        Write16(buffer, ref header, query.Id);
        var flags = 0x8000 | (query.Flags & 0x0110) | (answer.ResponseCode & 15);
        if (answer.Authoritative)
            flags |= 0x0400;
        if (truncated)
            flags |= 0x0200;
        Write16(buffer, ref header, (ushort)flags);
        Write16(buffer, ref header, (ushort)(query.Question is null ? 0 : 1));
        Write16(buffer, ref header, answers);
        Write16(buffer, ref header, authority);
        Write16(buffer, ref header, additional);
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
            var owner = query.Question is { } question && rrset.Key.Owner.Equals(question.Name) ? new byte[] { 0xc0, 0x0c } : values[0].Record.GetOwnerWire();
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
