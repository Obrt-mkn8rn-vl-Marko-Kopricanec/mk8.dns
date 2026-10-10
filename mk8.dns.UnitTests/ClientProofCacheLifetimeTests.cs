using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofCacheLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HitsAgeCompleteMaterialWithoutRefillingStoredLifetime(bool wallOnly)
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture),
            maximumPositiveTtl: 10, maximumNegativeTtl: 5);
        await using var lifetime = cache.ConfigureAwait(true);
        var question = ClientProofFixture.Question();
        var first = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(10U, first.AuthenticatedTtl);
        Assert.Single(ClientProofFixture.Proof(first).AnswerSignatures);
        if (wallOnly) fixture.Clock.SetWall(103);
        else fixture.Clock.Advance(3);
        for (var index = 0; index < 3; index++)
        {
            var hit = await cache.ResolveDnssecAsync(question, CancellationToken.None);
            Assert.Equal(7U, hit.AuthenticatedTtl);
            Assert.True(DnssecClientResponseProjection.TryPrepare(hit, question, dnssecOk: true, out var prepared));
            Assert.All(prepared.Answers, record => Assert.Equal(7U, record.Ttl));
        }
        fixture.Clock.SetWall(100); fixture.Clock.SetMonotonic(0);
        Assert.Equal(7U, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).AuthenticatedTtl);
        Assert.Equal(2, fixture.Calls.Count);
        cache.Clear();
        Assert.NotNull((await cache.ResolveDnssecAsync(question, CancellationToken.None)).ClientProof);
        Assert.Equal(4, fixture.Calls.Count);
    }

    [Fact]
    public async Task FractionalAgingSpendsOncePerStoredReceiptAndQueuedDeliverySpendsAgain()
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture),
            maximumPositiveTtl: 10, maximumNegativeTtl: 5);
        await using var lifetime = cache.ConfigureAwait(true);
        var question = ClientProofFixture.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(0.01);
        var hit = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(9U, hit.AuthenticatedTtl);
        Assert.Equal(9U, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).AuthenticatedTtl);
        fixture.Clock.Advance(1);
        Assert.True(DnssecClientResponseProjection.TryPrepare(hit, question, dnssecOk: true, out var prepared));
        Assert.Equal(8U, prepared.RemainingTtl);
        Assert.Equal(2, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CandidateTtlAndWindowFenceHitsAndImmediateEncoding(bool window)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question();
        fixture.Transform = reply =>
        {
            if (!reply.Question.Equals(question)) return reply;
            var data = reply.Answers.Where(record => record.Type == 1).ToArray();
            var extra = fixture.Sign(data, window: window ? new DnssecSignatureWindow(100, 103) : null);
            return OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers, window ? extra : extra.WithTtl(3)]);
        };
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture));
        await using var lifetime = cache.ConfigureAwait(true);
        var first = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(3U, first.AuthenticatedTtl);
        fixture.Clock.Advance(1);
        var hit = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(2U, hit.AuthenticatedTtl);
        foreach (var dnssecOk in new[] { false, true })
        {
            var query = ClientMessageFixture.Query(dnssecOk: dnssecOk);
            Assert.True(DnssecClientMessageCodec.TryEncode(query, hit, tcp: true, recursionAvailable: true,
                authenticatedDataAllowed: true, out var message));
            var decoded = ClientMessageFixture.Decode(message, query);
            Assert.All(decoded.Answers, record => Assert.Equal(2U, record.Ttl));
            Assert.Equal(dnssecOk, (decoded.Flags & 0x20) != 0);
        }
        Assert.Equal(2, fixture.Calls.Count);
        fixture.Clock.Advance(3);
        Assert.False(DnssecClientResponseProjection.TryPrepare(hit, question, dnssecOk: true, out _));
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.True(fixture.Calls.Count > 2);
        Assert.Equal(1, cache.Statistics.Expirations);
    }

    [Fact]
    public async Task ZeroTtlAuthenticatesWithoutStorageOrProjection()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords[0] = fixture.RootRecords[0].WithTtl(0);
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture));
        await using var lifetime = cache.ConfigureAwait(true);
        var question = ClientProofFixture.Question();
        for (var index = 0; index < 2; index++)
        {
            var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
            Assert.Equal(0U, result.AuthenticatedTtl);
            Assert.False(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk: true, out _));
        }
        Assert.Equal(0, cache.Statistics.Entries);
        Assert.Equal(4, fixture.Calls.Count);
    }
}
