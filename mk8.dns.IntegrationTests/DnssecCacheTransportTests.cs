using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class DnssecCacheTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task NativeAuthenticatedResultsCacheExactDataNegativesAliasesAndDs(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false, dname: true);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [root.Server], child.Server.Port, time: zones.Clock);
        var cache = new CachingDnssecResolver(resolver);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        foreach (var question in new[] { Query("www.child.example.", 1), Query("www.child.example.", 28),
            Query("missing.child.example.", 1), Query("alias.example.", 1), Query("child.example.", 43), Query("www.branch.example.", 1) })
        {
            var fresh = await cache.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
            var rootRequests = root.Requests.Count; var childRequests = child.Requests.Count;
            var cached = await cache.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome);
            Assert.Equal(fresh.ResponseCode, cached.ResponseCode);
            Assert.Equal(Bytes(fresh.Answers), Bytes(cached.Answers));
            Assert.Equal(Bytes(fresh.Authority), Bytes(cached.Authority));
            Assert.Equal(rootRequests, root.Requests.Count); Assert.Equal(childRequests, child.Requests.Count);
        }
        Assert.Equal(6, cache.Statistics.Hits);
        Assert.Contains(root.Requests, request => request.Question.Type == 43 && request.Tcp == tcp);
        cache.Clear(); Assert.Equal(0, cache.Statistics.Entries);
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(false, true, true)]
    [InlineData(true, true, true)]
    public async Task NativeUnsignedOrCorruptDataCannotGainCacheLease(bool ipv6, bool tcp, bool corrupt)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: !corrupt);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [root.Server], child.Server.Port, time: zones.Clock);
        var cache = new CachingDnssecResolver(resolver);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = Query("www.child.example.", 1);
        for (var index = 0; index < 2; index++)
        {
            var result = await cache.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
            Assert.Equal(corrupt ? DnssecResolutionOutcome.Failure : DnssecResolutionOutcome.UnsignedDelegation, result.Outcome);
            Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        }
        Assert.Equal(0, cache.Statistics.Entries);
        Assert.Equal(0, cache.Statistics.Hits);
        Assert.Empty(child.Requests);
    }

    private static DnsQuestion Query(string name, ushort type) => new(DnsName.Parse(name), type, 1);
    private static string[] Bytes(IReadOnlyList<DnsRecord> records)
        => records.Select(record => record.Owner + ":" + record.Type + ":" + record.Ttl + ":" + Convert.ToHexString(record.GetData())).ToArray();
}
