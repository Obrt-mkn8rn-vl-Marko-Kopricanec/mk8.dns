using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecursiveCacheTests
{
    private static readonly DnsQuestion Question = Query("www.example.");

    [Fact]
    public async Task PositiveLifetimeUsesMonotonicTimeAndCannotRegainTtl()
    {
        var clock = new RecursiveCacheClock();
        var source = new RecursiveCacheFixture.ImmediateResolver(q => Positive(q, 10));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source, time: clock);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        Assert.Equal(10u, Assert.Single((await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true)).Answers).Ttl);
        clock.Set(TimeSpan.FromSeconds(2.1));
        Assert.Equal(7u, Assert.Single((await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true)).Answers).Ttl);
        clock.Set(TimeSpan.FromSeconds(1));
        clock.WallTime = DateTimeOffset.UnixEpoch.AddYears(40);
        Assert.Equal(7u, Assert.Single((await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true)).Answers).Ttl);
        Assert.Equal(1, source.Calls);
        clock.Set(TimeSpan.FromSeconds(10));
        Assert.Equal(10u, Assert.Single((await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true)).Answers).Ttl);
        Assert.Equal(2, source.Calls);
        Assert.Equal(1, cache.Statistics.Expirations);
        Assert.Equal(0, clock.ActiveTimers);
    }

    [Fact]
    public async Task CanonicalKeysAndImmutableOpaqueBytesSurviveTtlChanges()
    {
        var wire = DnsName.Parse("www.example.").ToWire(); wire[1] = (byte)'W';
        byte[] raw = [0xc0, 12, 255];
        var source = new RecursiveCacheFixture.ImmediateResolver(_ => new DnsAnswer(0, false, [new DnsRecord(wire, 65280, 40, raw)], [], []));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var first = await cache.ResolveAsync(Query("WWW.Example.", 65280), CancellationToken.None).ConfigureAwait(true);
        Assert.Single(first.Answers).GetData()[0] = 0;
        raw[0] = 0;
        var second = await cache.ResolveAsync(Query("www.example.", 65280), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(new byte[] { 0xc0, 12, 255 }, Assert.Single(second.Answers).GetData());
        Assert.Equal((byte)'W', Assert.Single(second.Answers).GetOwnerWire()[1]);
        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public async Task WholeAliasChainExpiresAtItsShortestRecord()
    {
        var clock = new RecursiveCacheClock();
        var target = DnsName.Parse("target.other.");
        var source = new RecursiveCacheFixture.ImmediateResolver(_ => new DnsAnswer(0, false,
            [new DnsRecord(Question.Name, 5, 2, target.ToWire()), new DnsRecord(target, 1, 30, new byte[] { 192, 0, 2, 42 })], [], []));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source, time: clock);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        _ = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        clock.Set(TimeSpan.FromSeconds(1));
        var hit = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(new uint[] { 1, 29 }, hit.Answers.Select(record => record.Ttl));
        clock.Set(TimeSpan.FromSeconds(2));
        _ = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, source.Calls);
    }

    [Theory]
    [InlineData(0, 2)]
    [InlineData(3, 1)]
    public async Task NegativeKeyAndSoaLifetimeDistinguishNodataFromNxdomain(int code, int expectedCalls)
    {
        var clock = new RecursiveCacheClock();
        var source = new RecursiveCacheFixture.ImmediateResolver(_ => Negative((byte)code, 100, 8));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source, maximumPositiveTtl: 10, maximumNegativeTtl: 5, time: clock);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var initial = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(5u, Assert.Single(initial.Authority).Ttl);
        clock.Set(TimeSpan.FromSeconds(2));
        var cached = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(3u, Assert.Single(cached.Authority).Ttl);
        _ = await cache.ResolveAsync(Question with { Type = 28 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(expectedCalls, source.Calls);
        clock.Set(TimeSpan.FromSeconds(5));
        _ = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(expectedCalls + 1, source.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public async Task AliasNegativeDoesNotDeclareTheExistingAliasNameAbsent(int code)
    {
        var target = DnsName.Parse("missing.other.");
        var source = new RecursiveCacheFixture.ImmediateResolver(q => q.Type == 5
            ? new DnsAnswer(0, false, [new DnsRecord(q.Name, 5, 30, target.ToWire())], [], [])
            : new DnsAnswer((byte)code, false, [new DnsRecord(q.Name, 5, 30, target.ToWire())], [Soa("other.", 30, 30)], []));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        _ = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(code, (await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true)).ResponseCode);
        var cname = await cache.ResolveAsync(Question with { Type = 5 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, cname.ResponseCode);
        Assert.Equal(5, Assert.Single(cname.Answers).Type);
        _ = await cache.ResolveAsync(Question with { Type = 28 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(3, source.Calls);
    }

    [Fact]
    public async Task DnameAliasForADnameQuestionStillUsesTheTerminalNegativeSoa()
    {
        var clock = new RecursiveCacheClock();
        var question = Query("www.sub.example.", 39);
        var terminal = DnsName.Parse("www.other.");
        var source = new RecursiveCacheFixture.ImmediateResolver(_ => new DnsAnswer(0, false,
            [new DnsRecord(DnsName.Parse("sub.example."), 39, 40, DnsName.Parse("other.").ToWire()),
             new DnsRecord(question.Name, 5, 40, terminal.ToWire())], [Soa("other.", 5, 5)], []));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source, time: clock);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        _ = await cache.ResolveAsync(question, CancellationToken.None).ConfigureAwait(true);
        clock.Set(TimeSpan.FromSeconds(2));
        var hit = await cache.ResolveAsync(question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(3u, Assert.Single(hit.Authority).Ttl);
        clock.Set(TimeSpan.FromSeconds(5));
        _ = await cache.ResolveAsync(question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, source.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(6)]
    public async Task IncompleteAndFailureRepliesAreNeverRetained(int code)
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(_ => new DnsAnswer((byte)code, false, [], [], []));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        _ = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        _ = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, source.Calls);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ZeroPositiveOrNegativeTtlIsOnlyUsedForCurrentResolution(bool negative)
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => negative ? Negative(3, 50, 0) : Positive(q, 0));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        _ = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        _ = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, source.Calls);
        Assert.Equal(0, cache.Statistics.PayloadBytes);
    }

    [Fact]
    public async Task RrsetMinimumAndPositiveCapApplyOnFirstDelivery()
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => new DnsAnswer(0, false,
            [new DnsRecord(q.Name, 1, 70, new byte[] { 192, 0, 2, 41 }), new DnsRecord(q.Name, 1, 50, new byte[] { 192, 0, 2, 42 })], [], []));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source, maximumPositiveTtl: 40, maximumNegativeTtl: 30, time: new RecursiveCacheClock());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var answer = await cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(new uint[] { 40, 40 }, answer.Answers.Select(record => record.Ttl));
    }

    [Fact]
    public async Task EntryQuotaEvictsLeastRecentlyUsedCompleteAnswer()
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => Positive(q, 300));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source, maximumEntries: 2);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        foreach (var name in new[] { "a.example.", "b.example.", "a.example.", "c.example.", "a.example." })
            _ = await cache.ResolveAsync(Query(name), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(3, source.Calls);
        Assert.Equal(1, cache.Statistics.Evictions);
        _ = await cache.ResolveAsync(Query("b.example."), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(4, source.Calls);
        Assert.Equal(2, cache.Statistics.Entries);
    }

    [Fact]
    public async Task PayloadQuotaIsIndependentOfEntryCount()
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => Positive(q, 300));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source, maximumEntries: 100, maximumPayloadBytes: 80);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        _ = await cache.ResolveAsync(Query("a.example."), CancellationToken.None).ConfigureAwait(true);
        _ = await cache.ResolveAsync(Query("b.example."), CancellationToken.None).ConfigureAwait(true);
        _ = await cache.ResolveAsync(Query("b.example."), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, source.Calls);
        Assert.Equal(52, cache.Statistics.PayloadBytes);
        Assert.Equal(1, cache.Statistics.Entries);
        Assert.Equal(1, cache.Statistics.Evictions);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OversizedWholeAnswersAreReturnedButNotCached(bool records)
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => records
            ? new DnsAnswer(0, false, Enumerable.Range(0, 513).Select(_ => new DnsRecord(q.Name, 1, 30, new byte[] { 192, 0, 2, 42 })), [], [])
            : new DnsAnswer(0, false, [new DnsRecord(q.Name, 65280, 30, new byte[65535])], [], []));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = records ? Question : Question with { Type = 65280 };
        _ = await cache.ResolveAsync(question, CancellationToken.None).ConfigureAwait(true);
        _ = await cache.ResolveAsync(question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, source.Calls);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidProviderRoleOrAdditionalDataFailsWithoutCaching(bool additional)
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => new DnsAnswer(0, !additional,
            [new DnsRecord(q.Name, 1, 30, new byte[] { 192, 0, 2, 42 })], [], additional ? new[] { Soa("example.", 30, 30) } : []));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => cache.ResolveAsync(Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, cache.Statistics.ActiveFlights);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(41, 1)]
    [InlineData(252, 1)]
    [InlineData(255, 1)]
    [InlineData(1, 3)]
    public async Task UnsupportedQuestionsAreRefusedBeforeAnyProviderAdmission(int type, int recordClass)
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => Positive(q, 30));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var answer = await cache.ResolveAsync(Question with { Type = (ushort)type, Class = (ushort)recordClass }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(5, answer.ResponseCode);
        Assert.Equal(0, source.Calls);
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
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    public async Task InvalidBoundsFailBeforeAnyWork(int invalid)
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => Positive(q, 30));
        await using var sourceLifetime = source.ConfigureAwait(true);
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachingRecursiveResolver(source,
            maximumEntries: invalid == 0 ? 0 : invalid == 1 ? 65537 : 4096,
            maximumPayloadBytes: invalid == 2 ? 0 : invalid == 3 ? 536870913 : 16777216,
            maximumFlights: invalid == 4 ? 0 : invalid == 5 ? 257 : 64,
            maximumWaiters: invalid == 6 ? 0 : invalid == 7 ? 65537 : 1024,
            maximumPositiveTtl: invalid == 8 ? 0u : invalid == 9 ? 604801u : invalid == 12 ? 1u : 86400u,
            maximumNegativeTtl: invalid == 10 ? 0u : invalid == 11 ? 86401u : 3600u,
            resolutionTimeout: invalid == 13 ? TimeSpan.FromMilliseconds(49) : invalid == 14 ? TimeSpan.FromSeconds(121) : null));
        Assert.Equal(0, source.Calls);
    }

    internal static DnsQuestion Query(string name, ushort type = 1) => new(DnsName.Parse(name), type, 1);
    internal static DnsAnswer Positive(DnsQuestion question, uint ttl, byte value = 42) => new(0, false,
        [new DnsRecord(question.Name, 1, ttl, new byte[] { 192, 0, 2, value })], [], []);
    internal static DnsAnswer Negative(byte code, uint ttl, uint minimum) => new(code, false, [], [Soa("example.", ttl, minimum)], []);
    internal static DnsRecord Soa(string origin, uint ttl, uint minimum)
    {
        var numbers = new byte[20];
        BinaryPrimitives.WriteUInt32BigEndian(numbers.AsSpan(16), minimum);
        return new DnsRecord(DnsName.Parse(origin), 6, ttl, [.. DnsName.Parse("ns." + origin).ToWire(), .. DnsName.Parse("hostmaster." + origin).ToWire(), .. numbers]);
    }
}
