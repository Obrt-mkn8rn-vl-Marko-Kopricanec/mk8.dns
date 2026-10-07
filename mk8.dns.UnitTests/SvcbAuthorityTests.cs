using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SvcbAuthorityTests
{
    [Fact]
    public void ApexAliasModeIsReturnedVerbatimAndDoesNotAliasOtherTypes()
    {
        var origin = DnsName.Parse("example.");
        var zone = ZoneMasterFileCodec.Import(origin, SvcbMasterFileTests.Header + "@ HTTPS 0 external.\n@ A 192.0.2.1\n");
        var catalog = new AuthoritativeCatalog([zone]);
        var https = catalog.Resolve(new DnsQuestion(origin, 65, 1));
        Assert.True(https.Authoritative);
        Assert.Empty(https.Additional);
        Assert.Equal(Convert.FromHexString("00000865787465726e616c00"), Assert.Single(https.Answers).GetData());
        Assert.Equal(new byte[] { 192, 0, 2, 1 }, Assert.Single(catalog.Resolve(new DnsQuestion(origin, 1, 1)).Answers).GetData());
    }

    [Fact]
    public void ServiceParameterBytesSurviveCnameAndWildcardSynthesis()
    {
        var zone = ZoneMasterFileCodec.Import(DnsName.Parse("example."), SvcbMasterFileTests.Header + "svc SVCB 1 . key65280=\\000\\255\nalias CNAME svc\n*.sub HTTPS 1 . alpn=h3\n");
        var catalog = new AuthoritativeCatalog([zone]);
        var chain = catalog.Resolve(new DnsQuestion(DnsName.Parse("alias.example."), 64, 1));
        Assert.Equal(new ushort[] { 5, 64 }, chain.Answers.Select(record => record.Type));
        Assert.Equal(DnsName.Parse("svc.example."), chain.Answers[1].Owner);
        Assert.Equal(Convert.FromHexString("000100ff00000200ff"), chain.Answers[1].GetData());
        var owner = DnsName.Parse("www.sub.example.");
        var wildcard = Assert.Single(catalog.Resolve(new DnsQuestion(owner, 65, 1)).Answers);
        Assert.Equal(owner, wildcard.Owner);
        Assert.Equal(Convert.FromHexString("00010000010003026833"), wildcard.GetData());
    }

    [Fact]
    public void WholeTypedServiceRrsetTruncatesWithoutSplittingParametersAndTcpIsComplete()
    {
        var text = SvcbMasterFileTests.Header + "svc HTTPS 1 . key65280=" + new string('a', 450) + "\nsvc HTTPS 2 . key65280=" + new string('b', 450) + "\n";
        var zone = ZoneMasterFileCodec.Import(DnsName.Parse("example."), text);
        var query = DnsMessageCodec.DecodeQuery(Convert.FromHexString("abcd0100000100000000000003737663076578616d706c650000410001"));
        var answer = new AuthoritativeCatalog([zone]).Resolve(query.Question!);
        var udp = DnsMessageCodec.EncodeResponse(query, answer, tcp: false);
        Assert.Equal(29, udp.Length);
        Assert.Equal(0x8700, BinaryPrimitives.ReadUInt16BigEndian(udp.AsSpan(2)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(udp.AsSpan(6)));
        var tcp = DnsMessageCodec.EncodeResponse(query, answer, tcp: true);
        Assert.Equal(967, tcp.Length);
        Assert.Equal(0x8500, BinaryPrimitives.ReadUInt16BigEndian(tcp.AsSpan(2)));
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(tcp.AsSpan(6)));
        Assert.Equal(Convert.FromHexString("000100ff0001c2"), tcp.AsSpan(41, 7).ToArray());
        Assert.Equal(new string('a', 450).Select(character => (byte)character), tcp.AsSpan(48, 450).ToArray());
        Assert.Equal(Convert.FromHexString("000200ff0001c2"), tcp.AsSpan(510, 7).ToArray());
        Assert.Equal(new string('b', 450).Select(character => (byte)character), tcp.AsSpan(517, 450).ToArray());
    }
}
