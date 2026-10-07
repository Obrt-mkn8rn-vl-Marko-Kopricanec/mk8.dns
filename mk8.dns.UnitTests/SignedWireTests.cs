using System.Buffers.Binary;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SignedWireTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UdpTruncationKeepsDataAndItsSignatureAtomicWhileTcpCarriesBoth(bool reserveTsig)
    {
        var record = LargeTxt();
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(record));
        var query = DnsMessageCodec.DecodeQuery(Query("large.example.", 16));
        var answer = catalog.Resolve(query.Question!, dnssecOk: true);
        var response = DnsMessageCodec.EncodeResponse(query, answer, tcp: false, [], 512, reserveTsig ? (ushort)100 : (ushort)0);
        Assert.NotEqual(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) & 0x0200);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)));
        var tcp = DnsMessageCodec.EncodeResponse(query, answer, tcp: true, [], 512, reserveTsig ? (ushort)100 : (ushort)0);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(tcp.AsSpan(2)) & 0x0200);
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(tcp.AsSpan(6)));
    }

    [Fact]
    public void OmittingAnOptionalAdditionalSignaturePairDoesNotSetTc()
    {
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(LargeTxt()));
        var additional = catalog.Resolve(SignedAuthorityFixture.Question("large.example.", 16), dnssecOk: true).Answers;
        var query = DnsMessageCodec.DecodeQuery(Query("www.example.", 1));
        var response = DnsMessageCodec.EncodeResponse(query, new DnsAnswer(0, true, [], [], additional), tcp: false, [], 512);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) & 0x0200);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10)));
    }

    [Fact]
    public async Task ApplicationUsesDoCopiesCdAndLeavesAdClear()
    {
        var catalog = SignedAuthorityFixture.Catalog(AuthorityFixture.Zone(DnssecFixture.A()));
        var app = new AuthoritativeApplication(catalog, new DnsMessageCodecAdapter(), "signed-wire");
        var query = Query("www.example.", 1);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(2), 0x0130);
        var signed = await app.ExchangeAsync(query, tcp: true, new byte[] { 127, 0, 0, 1 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(signed.AsSpan(6)));
        var flags = BinaryPrimitives.ReadUInt16BigEndian(signed.AsSpan(2));
        Assert.NotEqual(0, flags & 0x0010);
        Assert.Equal(0, flags & 0x0020);
        query[^4] = 0;
        var plain = await app.ExchangeAsync(query, tcp: true, new byte[] { 127, 0, 0, 1 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(plain.AsSpan(6)));
    }

    private static byte[] Query(string name, ushort type)
    {
        var query = AuthorityFixture.Query(name, type, 512);
        query[^4] = 0x80;
        return query;
    }

    private static DnsRecord LargeTxt() => AuthorityFixture.Record("large.example.", 16,
        new byte[] { 255 }.Concat(new byte[255]).Concat(new byte[] { 143 }).Concat(new byte[143]).ToArray());
}
