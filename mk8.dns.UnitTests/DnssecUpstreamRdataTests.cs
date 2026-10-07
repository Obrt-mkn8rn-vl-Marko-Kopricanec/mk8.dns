using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecUpstreamRdataTests
{
    [Fact]
    public void CompleteAlgorithm13ProofBytesAndOriginalOwnerCaseArePreserved()
    {
        using var fixture = new DnssecChainFixture();
        var nsec = new DnsRecord(DnsName.Parse("www.example."), 47, 300, [.. DnssecFixture.Name("z.example.", upper: true), .. Mk8.Dns.Engine.Dnssec.NsecBitmap.Encode([1, 46, 47])]);
        var signature = DnssecChainFixture.Sign([nsec], fixture.ParentZskRecord, fixture.ParentZsk);
        var owner = nsec.GetOwnerWire(); owner[1] = (byte)'W';
        var wire = DnssecUpstreamFixture.Packet(answers: [DnssecUpstreamFixture.RawRecord(owner, 47, nsec.GetData()), DnssecUpstreamFixture.Record(signature)],
            authority: [DnssecUpstreamFixture.Record(fixture.Delegation), DnssecUpstreamFixture.Record(fixture.ParentCskRecord)], additional: [DnssecUpstreamFixture.Opt()]);
        var evidence = UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server).Evidence;
        Assert.NotNull(evidence);
        Assert.Equal(owner, evidence.Answers[0].GetOwnerWire()); Assert.Equal(nsec.GetData(), evidence.Answers[0].GetData()); Assert.Equal(signature.GetData(), evidence.Answers[1].GetData());
        Assert.Equal(fixture.Delegation.GetData(), evidence.Authority[0].GetData()); Assert.Equal(fixture.ParentCskRecord.GetData(), evidence.Authority[1].GetData());
        Assert.True(fixture.Validator.TryAuthenticateRrset(fixture.Trust(), new DnsQuestion(nsec.Owner, 47, 1), [evidence.Answers[0]], [evidence.Answers[1]], out _));
    }

    [Fact]
    public void BadCryptographicMaterialIsEvidenceNotAuthenticatedStatus()
    {
        var key = DnssecUpstreamFixture.RawRecord([0xc0, 0x0c], 48, [0, 0, 0, 0]);
        byte[] signature = [.. new byte[18], 0, 255];
        var wire = DnssecUpstreamFixture.Packet(answers: [key, DnssecUpstreamFixture.RawRecord([0xc0, 0x0c], 46, signature)]);
        var evidence = UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server).Evidence;
        Assert.NotNull(evidence); Assert.True(evidence.AuthenticatedDataObserved); Assert.Equal(2, evidence.Answers.Count);
        Assert.Equal(signature, evidence.Answers[1].GetData());
    }

    [Theory]
    [InlineData(39)]
    [InlineData(46)]
    [InlineData(47)]
    public void ModernNameCompressionIsRefused(int type)
    {
        byte[] data = type == 46 ? [.. new byte[18], 0xc0, 0x0c, 1] : [0xc0, 0x0c, 1];
        var wire = DnssecUpstreamFixture.Packet(answers: [DnssecUpstreamFixture.RawRecord([0xc0, 0x0c], (ushort)type, data)]);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(12)]
    public void LegacyCompressedRdataNamesRemainCasePreserving(int type)
    {
        var wire = DnssecUpstreamFixture.Packet(answers: [DnssecUpstreamFixture.RawRecord([0xc0, 0x0c], (ushort)type, [0xc0, 0x0c])]); wire[13] = (byte)'W';
        var evidence = UpstreamMessageCodec.DecodeDnssecResponse(wire, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server).Evidence;
        Assert.NotNull(evidence); var data = evidence.Answers[0].GetData(); Assert.Equal((byte)'W', data[1]);
    }

    [Fact]
    public void DsStructuralLengthAndTotalMessageRecordBoundsAreEnforced()
    {
        var invalid = DnssecUpstreamFixture.Packet(answers: [DnssecUpstreamFixture.RawRecord([0xc0, 0x0c], 43, [0, 1, 13, 2, 0])]);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse(invalid, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server));
        var count = DnssecUpstreamFixture.Packet(); DnssecUpstreamFixture.Write16(count, 6, 513);
        Assert.Throws<FormatException>(() => UpstreamMessageCodec.DecodeDnssecResponse(count, 42, DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Server));
    }
}
