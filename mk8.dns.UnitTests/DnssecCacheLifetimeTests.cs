using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecCacheLifetimeTests
{
    [Fact]
    public async Task WholeAnswerUsesPolicyCapAndConservativeFractionalAging()
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(fixture.Resolver(), maximumPositiveTtl: 10, maximumNegativeTtl: 5);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        var fresh = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(10U, fresh.AuthenticatedTtl);
        Assert.Equal(10U, Assert.Single(fresh.Answers).Ttl);
        fixture.Clock.Advance(0.01);
        var cached = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(9U, cached.AuthenticatedTtl);
        fixture.Clock.SetMonotonic(0);
        fixture.Clock.SetWall(100);
        Assert.Equal(9U, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).AuthenticatedTtl);
        Assert.Equal(2, fixture.Calls.Count);
    }

    [Theory]
    [InlineData("www.example.", 28, 0)]
    [InlineData("missing.example.", 1, 3)]
    public async Task NegativeWholeAnswerHonorsSoaMinimumAndNegativePolicy(string name, int type, int code)
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(fixture.Resolver(), maximumNegativeTtl: 8);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question(name, (ushort)type);
        var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(code, result.ResponseCode);
        Assert.Equal(8U, result.AuthenticatedTtl);
        Assert.Equal(8U, Assert.Single(result.Authority).Ttl);
        fixture.Clock.Advance(3);
        Assert.Equal(5U, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).AuthenticatedTtl);
        Assert.Equal(2, fixture.Calls.Count);
    }

    [Fact]
    public async Task ZeroTtlAuthenticatesButNeverCreatesEntry()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords[0] = fixture.RootRecords[0].WithTtl(0);
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        for (var index = 0; index < 2; index++)
        {
            var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
            Assert.Equal(0U, result.AuthenticatedTtl);
        }
        Assert.Equal(0, cache.Statistics.Entries);
        Assert.Equal(4, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ObservedExpiryDoesNotReviveAfterClockRollback(bool wallOnly)
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        if (wallOnly) fixture.Clock.SetWall(10_001);
        else fixture.Clock.SetMonotonic(301);
        Assert.Equal(wallOnly ? DnssecResolutionOutcome.Failure : DnssecResolutionOutcome.Authenticated,
            (await cache.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        fixture.Clock.SetWall(100); fixture.Clock.SetMonotonic(0);
        // A new query may acquire fresh TTL after monotonic-only expiry, but the old cache entry never revives.
        var calls = fixture.Calls.Count;
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(wallOnly ? 0 : 1, cache.Statistics.Hits);
        if (!wallOnly) Assert.Equal(calls, fixture.Calls.Count);
        Assert.True(fixture.Calls.Count > 2);
        Assert.Equal(1, cache.Statistics.Expirations);
    }

    [Fact]
    public async Task UnusedCandidateSignatureWindowBoundsCacheLease()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type != 1) return reply;
            var data = reply.Answers.Where(record => record.Type == 1).ToArray();
            return OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers, fixture.Sign(data, window: new DnssecSignatureWindow(100, 103))]);
        };
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        var first = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(3U, first.AuthenticatedTtl);
        fixture.Clock.SetWall(104);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        fixture.Clock.SetWall(100);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        Assert.Equal(0, cache.Statistics.Hits);
    }

    [Fact]
    public async Task RoutingSignatureExpiryForcesReacquisition()
    {
        using var fixture = new NameserverDnssecFixture { AddressWindow = new DnssecSignatureWindow(100, 103) };
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var first = await cache.ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(3U, first.AuthenticatedTtl);
        var calls = fixture.Calls.Count;
        fixture.Clock.SetWall(104);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await cache.ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None)).Outcome);
        Assert.True(fixture.Calls.Count > calls);
        Assert.Equal(0, cache.Statistics.Entries);
    }
}
