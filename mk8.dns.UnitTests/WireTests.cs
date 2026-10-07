using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class WireTests
{
    [Fact]
    public void WireResponsePreservesQuestionCaseIdAndRdWithoutRaOrAd()
    {
        var request = AuthorityFixture.Query("WWW.Example.", flags: 0x0130);
        var query = DnsMessageCodec.DecodeQuery(request);
        var response = DnsMessageCodec.EncodeResponse(query, new AuthoritativeCatalog([AuthorityFixture.Zone(AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 1]))]).Resolve(query.Question!), tcp: false);
        Assert.Equal(new byte[] { 0xab, 0xcd, 0x85, 0x10, 0, 1, 0, 1, 0, 0, 0, 0 }, response[..12]);
        Assert.Equal(request[12..], response[12..request.Length]);
        Assert.Equal(new byte[] { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 1 }, response[request.Length..]);
    }

    [Theory]
    [InlineData(0, 512)]
    [InlineData(511, 512)]
    [InlineData(1232, 1232)]
    [InlineData(65535, 1232)]
    public void EdnsClampsAdvertisedSizeAndRespondsWithOpt(ushort advertised, ushort expected)
    {
        var query = DnsMessageCodec.DecodeQuery(AuthorityFixture.Query(edns: advertised));
        Assert.Equal(expected, query.UdpPayloadSize);
        var response = DnsMessageCodec.EncodeResponse(query, new DnsAnswer(5, false, [], [], []), tcp: false);
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10)));
        Assert.Equal(new byte[] { 0, 0, 41, 4, 0xd0, 0, 0, 0, 0, 0, 0 }, response[^11..]);
    }

    [Fact]
    public void BadversHasExtendedRcodeAndNoAnswerData()
    {
        var query = DnsMessageCodec.DecodeQuery(AuthorityFixture.Query(edns: 1232, version: 1));
        var response = DnsMessageCodec.EncodeResponse(query, new DnsAnswer(0, true, [AuthorityFixture.Record("www.example.", 1, [192, 0, 2, 1])], [], []), tcp: false);
        Assert.Equal((byte)0x81, response[2]);
        Assert.Equal((byte)0, response[3]);
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)));
        Assert.Equal(new byte[] { 0, 0, 41, 4, 0xd0, 1, 0, 0, 0, 0, 0 }, response[^11..]);
    }

    [Fact]
    public void UdpTruncatesWholeRrsetsAndTcpRetainsThem()
    {
        var data = new byte[251];
        data[0] = 250;
        var second = (byte[])data.Clone();
        second[1] = 120;
        var records = new[] { AuthorityFixture.Record("www.example.", 16, data), AuthorityFixture.Record("www.example.", 16, second) };
        var query = DnsMessageCodec.DecodeQuery(AuthorityFixture.Query(type: 16));
        var answer = new DnsAnswer(0, true, records, [], []);
        var udp = DnsMessageCodec.EncodeResponse(query, answer, tcp: false);
        Assert.True(udp.Length <= 512);
        Assert.Equal((byte)0x87, udp[2]);
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(udp.AsSpan(6)));
        var tcp = DnsMessageCodec.EncodeResponse(query, answer, tcp: true);
        Assert.True(tcp.Length > 512);
        Assert.Equal((byte)0x85, tcp[2]);
        Assert.Equal((ushort)2, BinaryPrimitives.ReadUInt16BigEndian(tcp.AsSpan(6)));
    }

    [Theory]
    [InlineData("abcd0100000200000000000003777777076578616d706c650000010001")]
    [InlineData("abcd01000001000000000000c00c00010001")]
    [InlineData("abcd01000001000000000000c01c00010001")]
    [InlineData("abcd010000010000000000004000010001")]
    [InlineData("abcd01000001000000000000037777")]
    [InlineData("abcd01000001000000000000000001000100")]
    public void MalformedNameCountOrTrailingDataFailsClosed(string hex) => Assert.Throws<FormatException>(() => DnsMessageCodec.DecodeQuery(Convert.FromHexString(hex)));

    [Fact]
    public void DuplicateOptAndTruncatedOptionsAreRejected()
    {
        var duplicate = AuthorityFixture.Query(edns: 1232);
        duplicate[11] = 2;
        Assert.Throws<FormatException>(() => DnsMessageCodec.DecodeQuery(duplicate));
        var option = AuthorityFixture.Query(edns: 1232).Concat(new byte[] { 0, 10, 0, 2, 1 }).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(option.AsSpan(option.Length - 7), 5);
        Assert.Throws<FormatException>(() => DnsMessageCodec.DecodeQuery(option));
    }

    [Fact]
    public void ErrorResponsesAreBoundedAndNeverReflectResponsesOrShortPackets()
    {
        Assert.Empty(DnsMessageCodec.EncodeError(new byte[11], 1));
        Assert.Empty(DnsMessageCodec.EncodeError(AuthorityFixture.Query(flags: 0x8100), 1));
        Assert.Equal(new byte[] { 0xab, 0xcd, 0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0 }, DnsMessageCodec.EncodeError(AuthorityFixture.Query(), 1));
    }

    [Fact]
    public void CompressedRootOptAndDoFlagAreAcceptedWithoutEnablingValidation()
    {
        var root = AuthorityFixture.Query(".", edns: 1232);
        var opt = root.Length - 11;
        root[opt + 7] = 0x80;
        var compressed = root[..opt].Concat(new byte[] { 0xc0, 0x0c }).Concat(root[(opt + 1)..]).ToArray();
        var query = DnsMessageCodec.DecodeQuery(compressed);
        Assert.True(query.DnssecOk);
        var response = DnsMessageCodec.EncodeResponse(query, new DnsAnswer(5, false, [], [], []), tcp: false);
        Assert.Equal((byte)0x80, response[^4]);
        Assert.Equal((byte)0x05, response[3]);
    }

    [Fact]
    public void MissingRoomForRequiredGlueSetsTc()
    {
        var query = DnsMessageCodec.DecodeQuery(AuthorityFixture.Query("child.example."));
        var ns = AuthorityFixture.Record("child.example.", 2, DnsName.Parse("ns.child.example.").ToWire());
        var glue = Enumerable.Range(1, 40).Select(index => AuthorityFixture.Record("ns.child.example.", 1, [192, 0, 2, (byte)index])).ToArray();
        var response = DnsMessageCodec.EncodeResponse(query, new DnsAnswer(0, false, [], [ns], glue), tcp: false);
        Assert.Equal((byte)0x83, response[2]);
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(8)));
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10)));
    }

    [Fact]
    public void UnsupportedOpcodeDoesNotEnterTheQueryEngine()
    {
        var request = AuthorityFixture.Query(flags: 0x2900);
        Assert.Throws<NotSupportedException>(() => DnsMessageCodec.DecodeQuery(request));
        Assert.Equal((byte)0xa9, DnsMessageCodec.EncodeError(request, 4)[2]);
    }

    [Fact]
    public void NonQuestionOwnerRetainsItsConfiguredWireCase()
    {
        var original = AuthorityFixture.Query("TaRgEt.Example.")[12..^4];
        var record = new DnsRecord(original, 1, 300, new byte[] { 192, 0, 2, 1 });
        var query = DnsMessageCodec.DecodeQuery(AuthorityFixture.Query("alias.example."));
        var response = DnsMessageCodec.EncodeResponse(query, new DnsAnswer(0, true, [record], [], []), tcp: false);
        var offset = 12 + query.GetQuestionNameWire().Length + 4;
        Assert.Equal(original, response.AsSpan(offset, original.Length).ToArray());
    }

    [Fact]
    public void EveryTruncatedPrefixAndSeededMalformedCorpusTerminatesWithOnlyProtocolErrors()
    {
        var valid = AuthorityFixture.Query(edns: 1232);
        for (var length = 0; length < valid.Length; length++)
            Assert.Throws<FormatException>(() => DnsMessageCodec.DecodeQuery(valid.AsSpan(0, length)));
        var seed = new byte[8];
        for (var sample = 0; sample < 5000; sample++)
        {
            var packet = new byte[12 + (sample % 501)];
            BinaryPrimitives.WriteInt32BigEndian(seed, sample);
            for (var blockOffset = 0; blockOffset < packet.Length; blockOffset += 32)
            {
                BinaryPrimitives.WriteInt32BigEndian(seed.AsSpan(4), blockOffset);
                var block = SHA256.HashData(seed);
                block.AsSpan(0, Math.Min(block.Length, packet.Length - blockOffset)).CopyTo(packet.AsSpan(blockOffset));
            }
            packet[2] = 0;
            packet[3] = 0;
            packet[4] = 0;
            packet[5] = 1;
            packet.AsSpan(6, 6).Clear();
            try
            {
                var query = DnsMessageCodec.DecodeQuery(packet);
                Assert.InRange(query.GetQuestionNameWire().Length, 1, 255);
            }
            catch (FormatException)
            {
                // A malformed packet may only produce the bounded protocol failure.
            }
        }
    }
}
