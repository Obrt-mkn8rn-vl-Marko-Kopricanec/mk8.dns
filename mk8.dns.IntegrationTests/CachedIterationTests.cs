using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class CachedIterationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HitsExpiryAndClearControlActualHierarchyTraffic(bool ipv6)
    {
        var value = (byte)42;
        var hierarchy = new CacheHierarchy(ipv6, (query, _) => ValueTask.FromResult(Positive(query, value)));
        await using var hierarchyLifetime = hierarchy.ConfigureAwait(true);
        var clock = new CacheElapsedClock();
        var cache = new CachingRecursiveResolver(hierarchy.Resolver, time: clock);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = Q("www.example.", 1);
        Assert.Equal((byte)42, Assert.Single((await cache.ResolveAsync(question, hierarchy.Token).ConfigureAwait(true)).Answers).GetData()[3]);
        clock.Set(TimeSpan.FromSeconds(2));
        var hit = await cache.ResolveAsync(Q("WWW.Example.", 1), hierarchy.Token).ConfigureAwait(true);
        Assert.Equal(3u, Assert.Single(hit.Answers).Ttl);
        Assert.Equal(1, hierarchy.RootRequests);
        Assert.Equal(1, hierarchy.ChildRequests);
        value = 43;
        clock.Set(TimeSpan.FromSeconds(5));
        Assert.Equal((byte)43, Assert.Single((await cache.ResolveAsync(question, hierarchy.Token).ConfigureAwait(true)).Answers).GetData()[3]);
        cache.Clear();
        _ = await cache.ResolveAsync(question, hierarchy.Token).ConfigureAwait(true);
        Assert.Equal(3, hierarchy.RootRequests);
        Assert.Equal(3, hierarchy.ChildRequests);
        Assert.Equal(1, cache.Statistics.Expirations);
        Assert.False(hit.Authoritative);
        Assert.Empty(hit.Additional);
    }

    [Theory]
    [InlineData(false, (byte)0)]
    [InlineData(true, (byte)0)]
    [InlineData(false, (byte)3)]
    [InlineData(true, (byte)3)]
    public async Task NegativeSoaAgesAndKeysDistinguishNodataFromNxdomain(bool ipv6, byte code)
    {
        var hierarchy = new CacheHierarchy(ipv6, (_, _) => ValueTask.FromResult(Negative(code)));
        await using var hierarchyLifetime = hierarchy.ConfigureAwait(true);
        var clock = new CacheElapsedClock();
        var cache = new CachingRecursiveResolver(hierarchy.Resolver, time: clock);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        _ = await cache.ResolveAsync(Q("missing.example.", 1), hierarchy.Token).ConfigureAwait(true);
        clock.Set(TimeSpan.FromSeconds(2));
        var same = await cache.ResolveAsync(Q("missing.example.", 1), hierarchy.Token).ConfigureAwait(true);
        Assert.Equal(3u, Assert.Single(same.Authority).Ttl);
        var other = await cache.ResolveAsync(Q("missing.example.", 28), hierarchy.Token).ConfigureAwait(true);
        Assert.Equal(code, other.ResponseCode);
        Assert.Equal(code == 3 ? 1 : 2, hierarchy.ChildRequests);
        clock.Set(TimeSpan.FromSeconds(5));
        _ = await cache.ResolveAsync(Q("missing.example.", 1), hierarchy.Token).ConfigureAwait(true);
        Assert.Equal(code == 3 ? 2 : 3, hierarchy.RootRequests);
        Assert.Equal(hierarchy.RootRequests, hierarchy.ChildRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharedNetworkExchangeSurvivesOneCallerCancellation(bool ipv6)
    {
        var admitted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var hierarchy = new CacheHierarchy(ipv6, async (query, token) =>
        {
            admitted.TrySetResult();
            await release.Task.WaitAsync(token).ConfigureAwait(true);
            return Positive(query, 42);
        });
        await using var hierarchyLifetime = hierarchy.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(hierarchy.Resolver, time: new CacheElapsedClock());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        using var caller = new CancellationTokenSource();
        var first = cache.ResolveAsync(Q("www.example.", 1), caller.Token).AsTask();
        await admitted.Task.WaitAsync(hierarchy.Token).ConfigureAwait(true);
        var second = cache.ResolveAsync(Q("www.example.", 1), hierarchy.Token).AsTask();
        await caller.CancelAsync().ConfigureAwait(true);
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(hierarchy.Token)).ConfigureAwait(true);
        release.TrySetResult();
        Assert.Equal((byte)42, Assert.Single((await second.ConfigureAwait(true)).Answers).GetData()[3]);
        _ = await cache.ResolveAsync(Q("www.example.", 1), hierarchy.Token).ConfigureAwait(true);
        Assert.Equal(1, hierarchy.RootRequests);
        Assert.Equal(1, hierarchy.ChildRequests);
        Assert.Equal(1, cache.Statistics.Coalesced);
        Assert.Equal(0, cache.Statistics.ActiveFlights);
    }

    private static DnsQuestion Q(string name, ushort type) => new(DnsName.Parse(name), type, 1);
    private static DnsAnswer Positive(DnsQuery query, byte value)
    {
        var question = query.Question ?? throw new FormatException("Missing fixture question.");
        return new DnsAnswer(0, true, [new DnsRecord(question.Name, 1, 5, [192, 0, 2, value])], [], []);
    }
    private static DnsAnswer Negative(byte code)
    {
        var prefix = DnsName.Parse("ns.example.").ToWire().Concat(DnsName.Parse("hostmaster.example.").ToWire()).ToArray();
        var data = new byte[prefix.Length + 20];
        prefix.CopyTo(data, 0);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(prefix.Length), 1);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(data.Length - 4), 5);
        return new DnsAnswer(code, true, [], [new DnsRecord(DnsName.Parse("example."), 6, 10, data)], []);
    }

    private sealed class CacheElapsedClock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref ticks);
        internal void Set(TimeSpan elapsed) => Interlocked.Exchange(ref ticks, elapsed.Ticks);
    }
}
