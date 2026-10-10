using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientMessageMaterialTests
{
    [Theory]
    [InlineData("www.example.", 28, false)]
    [InlineData("www.example.", 28, true)]
    [InlineData("missing.example.", 1, false)]
    [InlineData("missing.example.", 1, true)]
    [InlineData("example.", 48, false)]
    [InlineData("example.", 48, true)]
    public async Task WireRetainsExactRequestedDataAndSelectedNegativeProof(string name, int type, bool dnssecOk)
    {
        ArgumentNullException.ThrowIfNull(name);
        using var fixture = new OnlineDnssecFixture();
        var query = ClientMessageFixture.Query(name, (ushort)type, dnssecOk: dnssecOk);
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(query.Question!, CancellationToken.None);
        fixture.Clock.Advance(5);
        Assert.True(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true, authenticatedDataAllowed: true, out var message));
        var decoded = ClientMessageFixture.Decode(message, query);
        Assert.Equal(result.ResponseCode, decoded.ResponseCode);
        Assert.Equal(dnssecOk, decoded.Answers.Concat(decoded.Authority).Any(record => record.Type == 46));
        Assert.All(decoded.Answers.Concat(decoded.Authority), record => Assert.Equal(result.AuthenticatedTtl - 5, record.Ttl));
        Assert.DoesNotContain(decoded.Answers.Concat(decoded.Authority), record => record.Type is 2 or 43);
        if (type == 48) Assert.Contains(decoded.Answers, record => record.Type == 48);
        else Assert.Contains(decoded.Authority, record => record.Type == 6);
        Assert.Equal(dnssecOk, (ClientMessageFixture.Flags(message) & 0x0020) != 0);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TruncationNeverSplitsDataSignatureGroupsOrClaimsAd(bool tcp)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Clear();
        // Large reserved TXT vectors exercise UDP and the DNS TCP message bound independently.
        var size = tcp ? 40_000 : 400;
        for (var index = 0; index < 2; index++)
        {
            var data = new byte[size];
            for (var offset = 0; offset < size;)
            {
                var length = Math.Min(255, size - offset - 1); data[offset] = (byte)length; offset += length + 1;
            }
            data[^1] = (byte)index;
            fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("large.example."), 16, 300, data));
        }
        var query = ClientMessageFixture.Query("large.example.", 16, size: 512);
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(query.Question!, CancellationToken.None);
        Assert.True(DnssecClientMessageCodec.TryEncode(query, result, tcp, recursionAvailable: true, authenticatedDataAllowed: true, out var message));
        Assert.InRange(message.Length, 12, tcp ? 65_535 : 512);
        Assert.NotEqual(0, ClientMessageFixture.Flags(message) & 0x0200);
        Assert.Equal(0, ClientMessageFixture.Flags(message) & 0x0020);
        Assert.Equal(new byte[4], message.AsSpan(6, 4).ToArray());
        Assert.True(Mk8.Dns.Wire.UpstreamMessageCodec.DecodeDnssecResponse(message, query.Id, query.Question!, OnlineDnssecFixture.RootServer).Truncated);
    }
}
