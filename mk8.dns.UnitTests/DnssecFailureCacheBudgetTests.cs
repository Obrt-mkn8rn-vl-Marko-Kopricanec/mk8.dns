using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecFailureCacheBudgetTests
{
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
    public void PolicyRejectsUnboundedLimitsBeforeSourceWork(int invalid)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecFailureCachePolicy(
            maximumEntries: invalid == 0 ? 0 : invalid == 1 ? 65537 : 1024,
            maximumPayloadBytes: invalid == 2 ? 0 : invalid == 3 ? 16777217 : 1048576,
            minimumTtl: invalid == 4 ? 0U : invalid == 5 ? 301U : invalid == 8 ? 3U : 1U,
            maximumTtl: invalid == 6 ? 0U : invalid == 7 ? 301U : invalid == 8 ? 2U : 300U));
    }

    [Fact]
    public async Task SeparateFailureQuotaUsesBoundedLruAndExactQuestionCharge()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(maximumEntries: 2));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        foreach (var name in new[] { "a.example.", "b.example.", "a.example.", "c.example.", "a.example." })
            await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(name), CancellationToken.None);
        Assert.Equal(3, fixture.Calls.Count);
        Assert.Equal(2, cache.FailureStatistics.Entries);
        Assert.Equal(158, cache.FailureStatistics.PayloadBytes);
        Assert.Equal(1, cache.FailureStatistics.Evictions);
        await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question("b.example."), CancellationToken.None);
        Assert.Equal(4, fixture.Calls.Count);
        cache.Clear();
        Assert.Equal(0, cache.FailureStatistics.Entries);
        Assert.Equal(0, cache.FailureStatistics.PayloadBytes);
    }

    [Theory]
    [InlineData(1, 0, 2)]
    [InlineData(79, 1, 0)]
    public async Task SerializedFailureBoundIsIndependentFromAuthenticatedPayloadBudget(int bytes, int entries, int rejected)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(maximumPayloadBytes: bytes), maximumPayloadBytes: 1);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        for (var index = 0; index < 2; index++) await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question("a.example."), CancellationToken.None);
        Assert.Equal(entries, cache.FailureStatistics.Entries);
        Assert.Equal(rejected, cache.FailureStatistics.AdmissionRejections);
        Assert.Equal(entries == 1 ? 1 : 2, fixture.Calls.Count);
        Assert.Equal(0, cache.Statistics.PayloadBytes);
    }

    [Fact]
    public void NullPolicyRefusesBeforeUpstreamWork()
    {
        using var fixture = new OnlineDnssecFixture();
        Assert.Throws<ArgumentNullException>(() => CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), null!));
        Assert.Empty(fixture.Calls);
    }
}
