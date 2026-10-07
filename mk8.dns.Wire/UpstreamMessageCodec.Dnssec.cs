using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Wire;

public static partial class UpstreamMessageCodec
{
    public static byte[] EncodeDnssecQuery(ushort id, DnsQuestion question)
    {
        var result = EncodeQuery(id, question);
        Write16(result, 2, 0x0010); // CD set; RD and AD remain clear.
        Write16(result, result.Length - 4, 0x8000); // DO in the EDNS flags.
        return result;
    }

    public static DnssecUpstreamResponse DecodeDnssecResponse(ReadOnlySpan<byte> message, ushort id,
        DnsQuestion question, DnsServerEndpoint server)
    {
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(server);
        Require(question.Name is not null && question.Class == 1 && question.Type is not (0 or 41 or >= 249 and <= 255));
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
            return new DnssecUpstreamResponse(null); // Never expose partial records or OPT metadata.
        var answers = Read16(message, 6);
        var authority = Read16(message, 8);
        var additional = Read16(message, 10);
        Require(answers + authority + additional <= DnsUpstreamEvidence.MaximumRecords);
        var opt = new EvidenceOpt();
        var answerRecords = ReadEvidenceSection(message, ref offset, answers, boundaries, allowOpt: false, opt);
        var authorityRecords = ReadEvidenceSection(message, ref offset, authority, boundaries, allowOpt: false, opt);
        var additionalRecords = ReadEvidenceSection(message, ref offset, additional, boundaries, allowOpt: true, opt);
        Require(offset == message.Length);
        try
        {
            var code = (ushort)((opt.ExtendedCode << 4) | (flags & 15));
            return new DnssecUpstreamResponse(new DnsUpstreamEvidence(question, server, id, flags, code,
                opt.Seen, opt.Payload, opt.Version, opt.Flags, answerRecords, authorityRecords, additionalRecords));
        }
        catch (ArgumentException error)
        {
            throw new FormatException("Invalid bounded DNSSEC acquisition evidence.", error);
        }
    }

    private static List<DnsRecord> ReadEvidenceSection(ReadOnlySpan<byte> message, ref int offset, int count,
        HashSet<int> boundaries, bool allowOpt, EvidenceOpt opt)
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
                Require(allowOpt && !opt.Seen && owner.Length == 1);
                opt.Seen = true;
                opt.Payload = recordClass;
                opt.ExtendedCode = (byte)(ttl >> 24);
                opt.Version = (byte)(ttl >> 16);
                opt.Flags = (ushort)ttl;
                while (offset < end)
                {
                    Require(end - offset >= 4);
                    var optionLength = Read16(message, offset + 2);
                    offset += 4;
                    Require(optionLength <= end - offset);
                    offset += optionLength;
                }
            }
            else
            {
                Require(recordClass == 1 && type != 0 && type is not (>= 249 and <= 255));
                var data = ExpandData(message, ref offset, end, type, boundaries);
                try { records.Add(new DnsRecord(owner, type, ttl > int.MaxValue ? 0 : ttl, data)); }
                catch (ArgumentException error) { throw new FormatException("Invalid stored upstream DNS record.", error); }
            }
            Require(offset == end);
        }
        return records;
    }

    private sealed class EvidenceOpt
    {
        internal bool Seen { get; set; }
        internal ushort Payload { get; set; }
        internal byte ExtendedCode { get; set; }
        internal byte Version { get; set; }
        internal ushort Flags { get; set; }
    }
}
