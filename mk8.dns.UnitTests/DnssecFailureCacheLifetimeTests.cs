using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecFailureCacheLifetimeTests
{
    [Fact]
    public async Task HitsDoNotExtendExpiryAndFailedRetriesDoubleUpToConfiguredCap()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(minimumTtl: 1, maximumTtl: 3));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(0.9);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Single(fixture.Calls);
        fixture.Clock.Advance(0.1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(2, fixture.Calls.Count);
        fixture.Clock.Advance(1.99);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(2, fixture.Calls.Count);
        fixture.Clock.Advance(0.01);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(3, fixture.Calls.Count);
        fixture.Clock.Advance(3);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(3);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(5, fixture.Calls.Count);
        Assert.Equal(4, cache.FailureStatistics.Expirations);
        Assert.Equal(5, cache.FailureStatistics.Stores);
    }

    [Fact]
    public async Task MonotonicHighWaterPreventsRevivalButWallClockIsNotFailureTtl()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(minimumTtl: 2, maximumTtl: 2));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.SetWall(100_000);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Single(fixture.Calls);
        fixture.Clock.SetMonotonic(2);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(2, fixture.Calls.Count);
        fixture.Clock.SetMonotonic(0);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.SetMonotonic(4);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(3, fixture.Calls.Count);
    }

    [Fact]
    public async Task SuccessAfterExpiryResetsBackoffIncludingZeroTtl()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(minimumTtl: 1, maximumTtl: 4));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(2);
        fixture.Override = null; fixture.RootRecords[0] = fixture.RootRecords[0].WithTtl(0);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        Assert.Equal(0, cache.FailureStatistics.Entries);
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var calls = fixture.Calls.Count;
        fixture.Clock.Advance(1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(calls + 1, fixture.Calls.Count);
    }

    [Fact]
    public async Task HoldDownStartsAtCompletedFailureAfterActualProviderWork()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => { fixture.Clock.Advance(100); return ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException()); };
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(minimumTtl: 1, maximumTtl: 1));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Single(fixture.Calls);
        fixture.Clock.Advance(1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(2, fixture.Calls.Count);
    }
}
