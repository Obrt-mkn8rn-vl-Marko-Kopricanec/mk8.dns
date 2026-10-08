using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecCacheConflictTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NewlyAuthenticatedExistenceInvalidatesOlderExactNameError(bool zero)
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question("missing.example.", 28);
        Assert.Equal(3, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).ResponseCode);
        fixture.RootRecords.Add(DnssecFixture.A(question.Name.ToString(), ttl: zero ? 0U : 300U));
        Assert.Equal(0, (await cache.ResolveDnssecAsync(question with { Type = 1 }, CancellationToken.None)).ResponseCode);
        Assert.Equal(0, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).ResponseCode);
        Assert.Equal(6, fixture.Calls.Count);
        Assert.Equal(0, cache.Statistics.Hits);
    }

    [Fact]
    public async Task NewlyAuthenticatedAbsenceInvalidatesEveryOlderTypeAtName()
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question("missing.example.");
        fixture.RootRecords.Add(DnssecFixture.A(question.Name.ToString()));
        Assert.Equal(0, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).ResponseCode);
        fixture.RootRecords.RemoveAt(fixture.RootRecords.Count - 1);
        Assert.Equal(3, (await cache.ResolveDnssecAsync(question with { Type = 28 }, CancellationToken.None)).ResponseCode);
        Assert.Equal(1, cache.Statistics.Entries);
        Assert.Equal(3, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).ResponseCode);
        Assert.Equal(6, fixture.Calls.Count);
        Assert.Equal(0, cache.Statistics.Hits);
    }

    [Fact]
    public async Task AliasNameErrorCannotBecomeOriginalNameAbsence()
    {
        using var fixture = new OnlineDnssecFixture();
        var alias = DnsName.Parse("alias.example.");
        fixture.RootRecords.Add(new DnsRecord(alias, 5, 300, DnsName.Parse("missing.child.example.").ToWire()));
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var first = await cache.ResolveDnssecAsync(new DnsQuestion(alias, 1, 1), CancellationToken.None);
        Assert.Equal(3, first.ResponseCode);
        Assert.Equal(5, Assert.Single(first.Answers).Type);
        var cname = await cache.ResolveDnssecAsync(new DnsQuestion(alias, 5, 1), CancellationToken.None);
        Assert.Equal(0, cname.ResponseCode);
        Assert.Equal(5, Assert.Single(cname.Answers).Type);
        Assert.Equal(2, cache.Statistics.Entries);
        Assert.Equal(0, cache.Statistics.Hits);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EarlierAdmittedCompletionCannotReplaceNewerGeneration(bool differentType)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = DnssecCacheResolutionTests.Question();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var prior = fixture.Default(question, OnlineDnssecFixture.RootServer);
        var terminalCalls = 0;
        fixture.Override = (query, server, _) => query.Type == 1 && Interlocked.Increment(ref terminalCalls) == 1
            ? new ValueTask<DnsUpstreamEvidence>(held.Task) : ValueTask.FromResult(fixture.Default(query, server));
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var older = cache.ResolveDnssecAsync(question, CancellationToken.None).AsTask();
        try
        {
            Assert.False(older.IsCompleted);
            fixture.RootRecords[0] = DnssecFixture.A(last: 99);
            var newer = await cache.ResolveDnssecAsync(question with { Type = differentType ? (ushort)28 : (ushort)1 }, CancellationToken.None);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, newer.Outcome);
        }
        finally { held.TrySetResult(prior); }
        Assert.Equal(1, Assert.Single((await older.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true)).Answers).GetData()[3]);
        var calls = fixture.Calls.Count;
        var current = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(99, Assert.Single(current.Answers).GetData()[3]);
        Assert.Equal(differentType ? calls + 2 : calls, fixture.Calls.Count);
    }
}
