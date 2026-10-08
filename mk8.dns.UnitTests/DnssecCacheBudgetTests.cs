using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecCacheBudgetTests
{
    [Fact]
    public async Task EntryBoundEvictsLeastRecentlyUsedWholeResult()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Add(DnssecFixture.A("a.example."));
        fixture.RootRecords.Add(DnssecFixture.A("b.example."));
        fixture.RootRecords.Add(DnssecFixture.A("c.example."));
        var cache = new CachingDnssecResolver(fixture.Resolver(), maximumEntries: 2);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        foreach (var name in new[] { "a.example.", "b.example.", "a.example.", "c.example.", "a.example." })
            await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(name), CancellationToken.None);
        Assert.Equal(6, fixture.Calls.Count);
        Assert.Equal(2, cache.Statistics.Entries);
        Assert.Equal(1, cache.Statistics.Evictions);
        await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question("b.example."), CancellationToken.None);
        Assert.Equal(8, fixture.Calls.Count);
        Assert.Equal(2, cache.Statistics.Evictions);
    }

    [Fact]
    public async Task SerializedPayloadBoundIncludesQuestionOriginAndRecord()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Add(DnssecFixture.A("a.example."));
        fixture.RootRecords.Add(DnssecFixture.A("b.example."));
        var cache = new CachingDnssecResolver(fixture.Resolver(), maximumPayloadBytes: 150);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        foreach (var name in new[] { "a.example.", "b.example.", "b.example." })
            await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(name), CancellationToken.None);
        Assert.Equal(4, fixture.Calls.Count);
        Assert.Equal(113, cache.Statistics.PayloadBytes);
        Assert.Equal(1, cache.Statistics.Entries);
        Assert.Equal(1, cache.Statistics.Evictions);
        cache.Clear();
        Assert.Equal(0, cache.Statistics.PayloadBytes);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Fact]
    public async Task OversizedAuthenticatedResultIsReturnedWithoutCacheAdmission()
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(fixture.Resolver(), maximumPayloadBytes: 1);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        for (var index = 0; index < 2; index++)
            Assert.Equal(DnssecResolutionOutcome.Authenticated,
                (await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None)).Outcome);
        Assert.Equal(4, fixture.Calls.Count);
        Assert.Equal(0, cache.Statistics.PayloadBytes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    public void InvalidBoundsRefuseBeforeProviderAdmission(int invalid)
    {
        using var fixture = new OnlineDnssecFixture();
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachingDnssecResolver(fixture.Resolver(),
            maximumEntries: invalid == 0 ? 0 : invalid == 1 ? 65537 : 4096,
            maximumPayloadBytes: invalid == 2 ? 0 : invalid == 3 ? 536870913 : 16777216,
            maximumRequests: invalid == 4 ? 0 : invalid == 5 ? 257 : 64,
            maximumPositiveTtl: invalid == 6 ? 0u : invalid == 7 ? 604801u : invalid == 10 ? 1u : 86400u,
            maximumNegativeTtl: invalid == 8 ? 0u : invalid == 9 ? 86401u : 3600u));
        Assert.Empty(fixture.Calls);
    }

    [Fact]
    public async Task CanonicalQuestionAndOpaqueResultBytesRemainOwned()
    {
        using var fixture = new OnlineDnssecFixture();
        var name = DnsName.Parse("opaque.example.");
        fixture.RootRecords.Add(new DnsRecord(name, 65280, 300, [0xc0, 12, 255]));
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var fresh = await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question("Opaque.Example.", 65280), CancellationToken.None);
        Assert.Single(fresh.Answers).GetData()[0] = 0;
        var hit = await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question("opaque.example.", 65280), CancellationToken.None);
        Assert.Equal(new byte[] { 0xc0, 12, 255 }, Assert.Single(hit.Answers).GetData());
        Assert.Throws<NotSupportedException>(() => ((IList<DnsRecord>)hit.Answers).Clear());
        Assert.Equal(2, fixture.Calls.Count);
    }
}
