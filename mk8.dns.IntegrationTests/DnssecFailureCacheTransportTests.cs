using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class DnssecFailureCacheTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task NativeCorrelatedSignatureFailureSuppressesNetworkUntilExpiryAndClear(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: true, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        root.Start(zones.Root);
        var clock = new FailureClock();
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [root.Server], time: clock);
        var cache = CachingDnssecResolver.CreateWithFailureCache(resolver, new DnssecFailureCachePolicy(minimumTtl: 1, maximumTtl: 2));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = new DnsQuestion(DnsName.Parse("www.example."), 1, 1);
        for (var index = 0; index < 2; index++) AssertFailure(await cache.ResolveDnssecAsync(question, deadline.Token));
        Assert.Equal(tcp ? 2 : 1, root.Requests.Count);
        clock.Advance(1);
        AssertFailure(await cache.ResolveDnssecAsync(question, deadline.Token));
        AssertFailure(await cache.ResolveDnssecAsync(question, deadline.Token));
        Assert.Equal(tcp ? 4 : 2, root.Requests.Count);
        clock.Advance(1);
        AssertFailure(await cache.ResolveDnssecAsync(question, deadline.Token));
        Assert.Equal(tcp ? 4 : 2, root.Requests.Count);
        clock.Advance(1);
        AssertFailure(await cache.ResolveDnssecAsync(question, deadline.Token));
        Assert.Equal(tcp ? 6 : 3, root.Requests.Count);
        cache.Clear();
        AssertFailure(await cache.ResolveDnssecAsync(question, deadline.Token));
        Assert.Equal(tcp ? 8 : 4, root.Requests.Count);
        Assert.Equal(4, cache.FailureStatistics.Stores);
        Assert.Equal(3, cache.FailureStatistics.Hits);
        Assert.Equal(0, cache.Statistics.ActiveRequests);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task NativeValidSignedNegativeUsesAuthenticatedCacheInsteadOfFailureCache(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        root.Start(zones.Root);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [root.Server], time: zones.Clock);
        var cache = CachingDnssecResolver.CreateWithFailureCache(resolver, new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = new DnsQuestion(DnsName.Parse("missing.example."), 1, 1);
        var first = await cache.ResolveDnssecAsync(question, deadline.Token);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, first.Outcome);
        Assert.Equal(3, first.ResponseCode);
        var calls = root.Requests.Count;
        var hit = await cache.ResolveDnssecAsync(question, deadline.Token);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, hit.Outcome);
        Assert.Equal(calls, root.Requests.Count);
        Assert.Equal(1, cache.Statistics.Hits);
        Assert.Equal(0, cache.FailureStatistics.Entries);
    }

    private static void AssertFailure(DnssecResolutionResult result)
    {
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Equal(2, result.ResponseCode);
        Assert.Equal(0U, result.AuthenticatedTtl);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
    }

    private sealed class FailureClock : TimeProvider
    {
        private long timestamp;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Volatile.Read(ref timestamp);
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
        internal void Advance(int seconds) => Interlocked.Add(ref timestamp, seconds * TimestampFrequency);
    }
}
