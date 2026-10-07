using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecUpstreamCodecTests
{
    [Fact]
    public void NewQueryRequestsLocalValidationEvidenceWhileLegacyProfileStaysClear()
    {
        var query = DnsMessageCodec.DecodeQuery(UpstreamMessageCodec.EncodeDnssecQuery(42, DnssecUpstreamFixture.Question));
        Assert.Equal((ushort)0x0010, query.Flags);
        Assert.True(query.DnssecOk); Assert.True(query.HasEdns); Assert.Equal((ushort)1232, query.UdpPayloadSize);
        var legacy = DnsMessageCodec.DecodeQuery(UpstreamMessageCodec.EncodeQuery(42, DnssecUpstreamFixture.Question));
        Assert.Equal((ushort)0, legacy.Flags); Assert.False(legacy.DnssecOk);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(4095)]
    public void CompleteExtendedRcodeAndObservedHeaderEdnsFlagsArePreserved(ushort code)
    {
        var flags = (ushort)(0x84b0 | (code & 15));
        var packet = DnssecUpstreamFixture.Packet(flags, additional: [DnssecUpstreamFixture.Opt((byte)(code >> 4), 7, 0x8001)]);
        var result = Assert.IsType<DnsUpstreamEvidence>(UpstreamMessageCodec.DecodeDnssecResponse(packet, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server).Evidence);
        Assert.Equal(code, result.ResponseCode); Assert.Equal(flags, result.Flags);
        Assert.True(result.Authoritative); Assert.True(result.AuthenticatedDataObserved); Assert.True(result.CheckingDisabledObserved);
        Assert.True(result.RecursionAvailable); Assert.True(result.DnssecOkObserved);
        Assert.Equal((byte)7, result.EdnsVersion); Assert.Equal((ushort)0x8001, result.EdnsFlags); Assert.Equal((ushort)4096, result.UdpPayloadSize);
        Assert.Same(DnssecUpstreamFixture.Question, result.Question); Assert.Same(DnssecUpstreamFixture.Server, result.Server);
    }

    [Fact]
    public void AbsentOptAndClearObservedFlagsDoNotBecomeAuthenticatedStatus()
    {
        var wire = DnssecUpstreamFixture.Packet(0x8000);
        var evidence = UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server).Evidence;
        Assert.NotNull(evidence); Assert.False(evidence.HasEdns); Assert.False(evidence.DnssecOkObserved);
        Assert.False(evidence.AuthenticatedDataObserved); Assert.False(evidence.Authoritative); Assert.False(evidence.CheckingDisabledObserved);
        Assert.Equal((ushort)0, evidence.UdpPayloadSize); Assert.Equal((byte)0, evidence.EdnsVersion);
    }

    [Fact]
    public void TcContainsNoPartialEvidenceEvenWithIncompleteRecords()
    {
        var wire = DnssecUpstreamFixture.Packet(0x8630, [DnssecUpstreamFixture.Record(DnssecFixture.A())]);
        var result = UpstreamMessageCodec.DecodeDnssecResponse(wire.AsSpan(0, wire.Length - 3), 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server);
        Assert.True(result.Truncated); Assert.Null(result.Evidence);
    }

    [Theory]
    [InlineData(0, 43)]
    [InlineData(2, 0x0010)]
    [InlineData(2, 0x8830)]
    [InlineData(2, 0x8470)]
    [InlineData(4, 2)]
    public void HeaderIdentityOpcodeAndReservedBitsAreRejected(int offset, ushort value)
    {
        var wire = DnssecUpstreamFixture.Packet(); DnssecUpstreamFixture.Write16(wire, offset, value);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void QuestionNameTypeAndClassAreCorrelated(int member)
    {
        var wire = DnssecUpstreamFixture.Packet(); var q = DnssecUpstreamFixture.Question;
        q = member switch { 0 => q with { Name = DnsName.Parse("other.example.") }, 1 => q with { Type = 28 }, _ => q with { Class = 3 } };
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, q, DnssecUpstreamFixture.Server));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void OptMustHaveOneRootOwnerAndBelongOnlyToAdditional(int violation)
    {
        var opt = DnssecUpstreamFixture.Opt();
        var wire = violation switch
        {
            0 => DnssecUpstreamFixture.Packet(answers: [opt]),
            1 => DnssecUpstreamFixture.Packet(authority: [opt]),
            2 => DnssecUpstreamFixture.Packet(additional: [opt, opt]),
            _ => DnssecUpstreamFixture.Packet(additional: [DnssecUpstreamFixture.RawRecord(DnsName.Parse("not-root.").ToWire(), 41, [])]),
        };
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void UnknownOptionsNeedValidLengthFraming(int malformed)
    {
        byte[] options = malformed == 0 ? [0, 1, 0] : [0, 1, 0, 3, 1];
        var wire = DnssecUpstreamFixture.Packet(additional: [DnssecUpstreamFixture.Opt(options: options)]);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server));
    }

    [Fact]
    public void UnknownFramedOptionsAndOpaqueDataDoNotBecomeControlRecords()
    {
        var value = DnssecUpstreamFixture.RawRecord([0xc0, 0x0c], 65280, [0xc0, 0x0c, 255]);
        var wire = DnssecUpstreamFixture.Packet(answers: [value], additional: [DnssecUpstreamFixture.Opt(options: [0xfd, 1, 0, 2, 0xc0, 0x0c])]);
        var result = UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server).Evidence;
        Assert.NotNull(result); Assert.Equal(new byte[] { 0xc0, 0x0c, 255 }, Assert.Single(result.Answers).GetData()); Assert.Empty(result.Additional);
    }

    [Fact]
    public void IncomingHighBitTtlIsZeroAndTrailingBytesAreRefused()
    {
        var row = DnssecUpstreamFixture.RawRecord([0xc0, 0x0c], 1, [192, 0, 2, 42]); BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(6), uint.MaxValue);
        var wire = DnssecUpstreamFixture.Packet(answers: [row]);
        var result = UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server).Evidence;
        Assert.NotNull(result); Assert.Equal(0U, Assert.Single(result.Answers).Ttl);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse([.. wire, 0], 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(13)]
    [InlineData(255)]
    public void CompressionTargetsOnlyEarlierKnownLabelBoundaries(int target)
    {
        var wire = DnssecUpstreamFixture.Packet(answers: [DnssecUpstreamFixture.RawRecord([0xc0, (byte)target], 1, [192, 0, 2, 42])]);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server));
    }
}
