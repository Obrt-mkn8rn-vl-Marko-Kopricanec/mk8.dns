using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofCacheBudgetTests
{
    [Fact]
    public void LegacySourceIsRejectedBeforeAcquisition()
    {
        using var fixture = new OnlineDnssecFixture();
        var error = Assert.Throws<ArgumentException>(() => CachingDnssecResolver.CreateWithClientProofCache(fixture.Resolver()));
        Assert.Equal("resolver", error.ParamName);
        Assert.Empty(fixture.Calls);
    }

    [Theory]
    [InlineData(0, 1024, 1)]
    [InlineData(1, 0, 1)]
    [InlineData(1, 1024, 0)]
    public void InvalidQuotaRefusesBeforeAcquisition(int entries, long bytes, int requests)
    {
        using var fixture = new OnlineDnssecFixture();
        Assert.Throws<ArgumentOutOfRangeException>(() => CachingDnssecResolver.CreateWithClientProofCache(
            ClientProofFixture.Resolver(fixture), entries, bytes, requests));
        Assert.Empty(fixture.Calls);
    }

    [Fact]
    public async Task CompleteProofAndReceiptAreChargedAndOversizeDoesNotStore()
    {
        using var fixture = new OnlineDnssecFixture();
        var source = ClientProofFixture.Resolver(fixture);
        var cache = CachingDnssecResolver.CreateWithClientProofCache(source);
        await using var lifetime = cache.ConfigureAwait(true);
        var question = ClientProofFixture.Question();
        var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var proof = ClientProofFixture.Proof(result);
        var bytes = 64L + question.Name.ToWire().Length + 4 + Assert.IsType<Mk8.Dns.Domain.DnsName>(result.Origin).ToWire().Length + 32
            + result.Answers.Concat(result.Authority).Concat(proof.AnswerSignatures).Concat(proof.Authority)
                .Sum(record => record.GetOwnerWire().Length + 10L + record.GetData().Length);
        Assert.Equal(bytes, cache.Statistics.PayloadBytes);
        var small = CachingDnssecResolver.CreateWithClientProofCache(source, maximumPayloadBytes: bytes - 1);
        await using var smallLifetime = small.ConfigureAwait(true);
        for (var index = 0; index < 2; index++)
            Assert.NotNull((await small.ResolveDnssecAsync(question, CancellationToken.None)).ClientProof);
        Assert.Equal(0, small.Statistics.Entries);
        Assert.Equal(6, fixture.Calls.Count);
    }

    [Fact]
    public async Task LruEvictsWholeMaterialWithoutDiscardingFreshDelivery()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Add(DnssecFixture.A("other.example."));
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture), maximumEntries: 1);
        await using var lifetime = cache.ConfigureAwait(true);
        var first = await cache.ResolveDnssecAsync(ClientProofFixture.Question(), CancellationToken.None);
        await cache.ResolveDnssecAsync(ClientProofFixture.Question("other.example."), CancellationToken.None);
        Assert.Equal(1, cache.Statistics.Entries);
        Assert.Equal(1, cache.Statistics.Evictions);
        Assert.True(DnssecClientResponseProjection.TryPrepare(first, first.Question, dnssecOk: true, out _));
        await cache.ResolveDnssecAsync(first.Question, CancellationToken.None);
        Assert.Equal(6, fixture.Calls.Count);
        Assert.Equal(2, cache.Statistics.Evictions);
    }
}
