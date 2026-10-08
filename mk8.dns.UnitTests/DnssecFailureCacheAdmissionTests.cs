using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecFailureCacheAdmissionTests
{
    [Fact]
    public async Task FailurePayloadQuotaEvictsEvenBelowEntryLimit()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(maximumEntries: 20, maximumPayloadBytes: 79));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        foreach (var name in new[] { "a.example.", "b.example.", "b.example." })
            await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(name), CancellationToken.None);
        Assert.Equal(2, fixture.Calls.Count);
        Assert.Equal(1, cache.FailureStatistics.Entries);
        Assert.Equal(79, cache.FailureStatistics.PayloadBytes);
        Assert.Equal(1, cache.FailureStatistics.Evictions);
    }

    [Fact]
    public async Task ExpiredHistoryEvictionResetsBackoffWithinTheSameBoundedQuota()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(maximumEntries: 1, minimumTtl: 1, maximumTtl: 300));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question("a.example.");
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        await cache.ResolveDnssecAsync(question with { Name = DnsName.Parse("b.example.") }, CancellationToken.None);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(5, fixture.Calls.Count);
        Assert.Equal(2, cache.FailureStatistics.Evictions);
    }

    [Fact]
    public async Task BackoffNeverExceedsThreeHundredSeconds()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(minimumTtl: 200));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(200);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(299.9);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(2, fixture.Calls.Count);
        fixture.Clock.Advance(0.1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(3, fixture.Calls.Count);
    }

    [Fact]
    public async Task CancellationBeforeAHitDoesNotSpendFailureCacheStatistics()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.ResolveDnssecAsync(question, new CancellationToken(canceled: true)).AsTask());
        Assert.Equal(0, cache.FailureStatistics.Hits);
        Assert.Single(fixture.Calls);
    }

    [Fact]
    public async Task DisposalRemovesExpiredHistoryAndClosesFurtherAdmission()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(100);
        await cache.DisposeAsync().ConfigureAwait(true);
        Assert.Equal(0, cache.FailureStatistics.Entries);
        Assert.Equal(0, cache.FailureStatistics.PayloadBytes);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => cache.ResolveDnssecAsync(question, CancellationToken.None).AsTask());
    }
}
