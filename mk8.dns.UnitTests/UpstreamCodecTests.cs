using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class UpstreamCodecTests
{
    private static readonly DnsQuestion Question = new(DnsName.Parse("www.example."), 1, 1);

    [Fact]
    public void IterativeQueryHasNoRecursionOrValidationFlags()
    {
        var query = DnsMessageCodec.DecodeQuery(UpstreamMessageCodec.EncodeQuery(42, Question));
        Assert.Equal((ushort)42, query.Id);
        Assert.Equal((ushort)0, query.Flags);
        Assert.Equal(Question, query.Question);
        Assert.True(query.HasEdns);
        Assert.False(query.DnssecOk);
        Assert.Equal((ushort)1232, query.UdpPayloadSize);
    }

    [Theory]
    [InlineData(0, 99)]
    [InlineData(2, 0)]
    [InlineData(2, 0x8840)]
    [InlineData(4, 2)]
    public void WrongIdentityFlagsOrQuestionCountFails(int offset, int value)
    {
        var wire = Packet([0xc0, 0x0c], 1, [192, 0, 2, 42]);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(offset), (ushort)value);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(wire, 42, Question));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void WrongQuestionTupleFails(int member)
    {
        var expected = member switch { 0 => Question with { Name = DnsName.Parse("other.example.") }, 1 => Question with { Type = 28 }, _ => Question with { Class = 3 } };
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 1, [192, 0, 2, 42]), 42, expected));
    }

    [Fact]
    public void TruncatedPartialRecordsAreNotParsedOrReturned()
    {
        var wire = Packet([0xc0, 0x0c], 1, [192, 0, 2, 42]);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(2), 0x8600);
        var parsed = UpstreamMessageCodec.DecodeResponse(wire.AsSpan(0, wire.Length - 3), 42, Question);
        Assert.True(parsed.Truncated);
        Assert.Empty(parsed.Answer.Answers);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(12)]
    [InlineData(3)]
    [InlineData(7)]
    public void LegacyNameRdataIsExpanded(int type)
    {
        var parsed = UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], (ushort)type, [0xc0, 0x0c]), 42, Question);
        Assert.Equal(Question.Name.ToWire(), Assert.Single(parsed.Answer.Answers).GetData());
    }

    [Theory]
    [InlineData(39)]
    [InlineData(47)]
    public void ModernForbiddenCompressionFails(int type)
    {
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], (ushort)type, [0xc0, 0x0c]), 42, Question));
    }

    [Fact]
    public void OpaqueUnknownDataAndNameCaseArePreserved()
    {
        byte[] data = [192, 12, 255, 0];
        var original = DnsName.Parse("www.example.").ToWire(); original[1] = (byte)'W';
        var record = Assert.Single(UpstreamMessageCodec.DecodeResponse(Packet(original, 65280, data), 42, Question).Answer.Answers);
        Assert.Equal(data, record.GetData());
        Assert.Equal(original, record.GetOwnerWire());
    }

    [Fact]
    public void HighTtlMeansZeroAndTrailingBytesFail()
    {
        var wire = Packet([0xc0, 0x0c], 1, [192, 0, 2, 42]);
        var start = 12 + Question.Name.ToWire().Length + 4;
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(start + 6), uint.MaxValue);
        Assert.Equal(0u, Assert.Single(UpstreamMessageCodec.DecodeResponse(wire, 42, Question).Answer.Answers).Ttl);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse([.. wire, 0], 42, Question));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(13)]
    [InlineData(255)]
    public void CompressionMustTargetAnEarlierKnownBoundary(int target)
    {
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(Packet([0xc0, (byte)target], 1, [192, 0, 2, 42]), 42, Question));
    }

    [Fact]
    public void RecordCountAndRdataBoundsAreEnforced()
    {
        var wire = Packet([0xc0, 0x0c], 1, [192, 0, 2, 42]);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(6), 513);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(wire, 42, Question));
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 1, [192, 0, 2]), 42, Question));
    }

    [Fact]
    public void SoaAndMxLegacyNamesAreExpandedInsideTheirRdataBounds()
    {
        var soa = UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 6, [0xc0, 0x0c, 0xc0, 0x0c, .. new byte[20]]), 42, Question);
        Assert.Equal((byte[])[.. Question.Name.ToWire(), .. Question.Name.ToWire(), .. new byte[20]], Assert.Single(soa.Answer.Answers).GetData());
        var mx = UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 15, [0, 10, 0xc0, 0x0c]), 42, Question);
        Assert.Equal((byte[])[0, 10, .. Question.Name.ToWire()], Assert.Single(mx.Answer.Answers).GetData());
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 6, [0xc0, 0x0c, 0xc0, 0x0c, .. new byte[19]]), 42, Question));
    }

    [Fact]
    public void NaptrCharacterStringsPrecedeTheReplacementName()
    {
        byte[] prefix = [0, 1, 0, 2, 1, (byte)'S', 0, 0];
        var value = UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 35, [.. prefix, 0xc0, 0x0c]), 42, Question);
        Assert.Equal((byte[])[.. prefix, .. Question.Name.ToWire()], Assert.Single(value.Answer.Answers).GetData());
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 35, [0, 1, 0, 2, 255]), 42, Question));
    }

    [Fact]
    public void A6ConditionalPrefixNameCannotBeCompressed()
    {
        byte[] value = [64, .. new byte[8], .. Question.Name.ToWire()];
        Assert.Equal(value, Assert.Single(UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 38, value), 42, Question).Answer.Answers).GetData());
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 38, [64, .. new byte[8], 0xc0, 0x0c]), 42, Question));
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeResponse(Packet([0xc0, 0x0c], 38, [129, 0]), 42, Question));
    }

    [Fact]
    public void ACompressedMaximumLengthNameAndPointerToPointerAreAdmitted()
    {
        var question = Question with { Name = DnsName.Parse(string.Concat(Enumerable.Repeat("a.", 127))) };
        var wire = Packet([0xc0, 0x0c], 1, [192, 0, 2, 42], question);
        Assert.Equal(question.Name, Assert.Single(UpstreamMessageCodec.DecodeResponse(wire, 42, question).Answer.Answers).Owner);
        wire = Packet([0xc0, 0x0c], 1, [192, 0, 2, 42]);
        var pointer = 16 + Question.Name.ToWire().Length;
        var appended = wire.AsSpan(pointer).ToArray(); appended[0] = (byte)(0xc0 | (pointer >> 8)); appended[1] = (byte)pointer;
        byte[] combined = [.. wire, .. appended]; BinaryPrimitives.WriteUInt16BigEndian(combined.AsSpan(6), 2);
        Assert.Equal(2, UpstreamMessageCodec.DecodeResponse(combined, 42, Question).Answer.Answers.Count);
    }

    private static byte[] Packet(byte[] owner, ushort type, byte[] data, DnsQuestion? question = null)
    {
        var name = (question ?? Question).Name.ToWire();
        var wire = new byte[12 + name.Length + 4 + owner.Length + 10 + data.Length];
        BinaryPrimitives.WriteUInt16BigEndian(wire, 42);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(2), 0x8400);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(6), 1);
        name.CopyTo(wire, 12);
        var offset = 12 + name.Length;
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(offset), 1);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(offset + 2), 1);
        offset += 4;
        owner.CopyTo(wire, offset); offset += owner.Length;
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(offset), type);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(offset + 2), 1);
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(offset + 4), 300);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(offset + 8), (ushort)data.Length);
        data.CopyTo(wire, offset + 10);
        return wire;
    }
}
