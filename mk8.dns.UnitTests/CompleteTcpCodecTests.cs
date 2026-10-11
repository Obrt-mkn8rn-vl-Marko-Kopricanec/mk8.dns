using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CompleteTcpCodecTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OversizedAuthenticatedMaterialNeverReturnsPartialTcpBytes(bool dnssecOk)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        CompleteTcpFixture.Install(f, 260);
        var result = await f.Resolver.ResolveDnssecAsync(CompleteTcpFixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome); Assert.Equal(260, result.Answers.Count);
        var query = ClientMessageFixture.Query(type: 16, dnssecOk: dnssecOk);
        Assert.True(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true,
            authenticatedDataAllowed: true, out var legacy));
        Assert.Equal(0x0200, ClientMessageFixture.Flags(legacy) & 0x0220);
        Assert.False(DnssecClientTcpMessageCodec.TryEncode(query, result, recursionAvailable: true,
            authenticatedDataAllowed: true, out var complete)); Assert.Empty(complete);
        Assert.Equal(2, f.Calls.Count); Assert.Equal(1, f.Resolver.Statistics.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NearMaximumCompleteAnswerRetainsAllSelectedRecordsAndOriginalLifetime(bool dnssecOk)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        CompleteTcpFixture.Install(f, 258);
        var result = await f.Resolver.ResolveDnssecAsync(CompleteTcpFixture.Question, CancellationToken.None).ConfigureAwait(true);
        var query = ClientMessageFixture.Query(type: 16, dnssecOk: dnssecOk);
        Assert.True(DnssecClientTcpMessageCodec.TryEncode(query, result, recursionAvailable: true,
            authenticatedDataAllowed: true, out var encoded));
        Assert.InRange(encoded.Length, 65000, 65535);
        var reply = ClientMessageFixture.Decode(encoded, query);
        Assert.Equal(dnssecOk ? 259 : 258, reply.Answers.Count); Assert.Equal(0, reply.Flags & 0x0200);
        Assert.Equal(dnssecOk, (reply.Flags & 32) != 0); Assert.All(reply.Answers, record => Assert.Equal(300U, record.Ttl));
        f.Advance(300);
        Assert.False(DnssecClientTcpMessageCodec.TryEncode(query, result, recursionAvailable: true,
            authenticatedDataAllowed: true, out var expired)); Assert.Empty(expired);
        Assert.Equal(2, f.Calls.Count);
    }
}
