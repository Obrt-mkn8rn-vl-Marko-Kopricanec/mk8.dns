using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecFailureCacheTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task CompletedResolutionFailuresSuppressExactQuestionWithoutAuthenticatingData(int failure)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (question, server, _) => failure switch
        {
            0 => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException("Controlled timeout.")),
            1 => ValueTask.FromException<DnsUpstreamEvidence>(new IOException("Controlled transport fault.")),
            2 => ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [], code: 2)),
            3 => ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [], code: 5)),
            _ => ValueTask.FromResult(OnlineDnssecFixture.Copy(fixture.Default(question, server), answers: [])),
        };
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var first = await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None);
        AssertFailure(first);
        var calls = fixture.Calls.Count;
        var second = await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question("WWW.Example."), CancellationToken.None);
        AssertFailure(second);
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(1, cache.FailureStatistics.Entries);
        Assert.Equal(1, cache.FailureStatistics.Hits);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CorruptedSelectedSignaturesAndAliasLoopsCacheOnlyEmptyFailure(bool alias)
    {
        using var fixture = new OnlineDnssecFixture();
        if (alias)
        {
            fixture.RootRecords.Clear();
            fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("www.example."), 5, 300, DnsName.Parse("www.example.").ToWire()));
        }
        else fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Select(record =>
        {
            if (record.Type != 46) return record;
            var bytes = record.GetData(); bytes[^1] ^= 1;
            return new DnsRecord(record.Owner, record.Type, record.Ttl, bytes);
        }).ToArray());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        AssertFailure(await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None));
        var calls = fixture.Calls.Count;
        AssertFailure(await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None));
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(1, cache.FailureStatistics.Stores);
    }

    [Fact]
    public async Task FailureKeysDoNotSuppressOtherNamesTypesOrClasses()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        foreach (var query in new[] { question, question with { Type = 28 }, question with { Name = DnsName.Parse("other.example.") }, question with { Class = 3 } })
            AssertFailure(await cache.ResolveDnssecAsync(query, CancellationToken.None));
        Assert.Equal(3, fixture.Calls.Count);
        Assert.Equal(3, cache.FailureStatistics.Entries);
        Assert.Equal(0, cache.FailureStatistics.Hits);
    }

    [Theory]
    [InlineData("outside.", 1, 1)]
    [InlineData("*.example.", 1, 1)]
    [InlineData("www.example.", 0, 1)]
    [InlineData("www.example.", 41, 1)]
    [InlineData("www.example.", 46, 1)]
    [InlineData("www.example.", 255, 1)]
    [InlineData("www.example.", 1, 3)]
    public async Task UnsupportedQuestionsNeverEstablishFailureState(string name, int type, int recordClass)
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        for (var index = 0; index < 2; index++)
            AssertFailure(await cache.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse(name), (ushort)type, (ushort)recordClass), CancellationToken.None));
        Assert.Empty(fixture.Calls);
        Assert.Equal(0, cache.FailureStatistics.Entries);
        Assert.Equal(0, cache.FailureStatistics.Hits);
    }

    [Theory]
    [InlineData("www.example.", 1)]
    [InlineData("www.example.", 28)]
    [InlineData("missing.example.", 1)]
    [InlineData("www.child.example.", 1)]
    public async Task AuthenticatedResultsAndUnsignedMarkersAreNotFailureEntries(string name, int type)
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = true };
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question(name, (ushort)type);
        var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.NotEqual(DnssecResolutionOutcome.Failure, result.Outcome);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(0, cache.FailureStatistics.Entries);
        Assert.Equal(0, cache.FailureStatistics.Hits);
    }

    [Fact]
    public async Task LegacyConstructorDoesNotCacheFailures()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        for (var index = 0; index < 2; index++) AssertFailure(await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None));
        Assert.Equal(2, fixture.Calls.Count);
        Assert.Equal(0, cache.FailureStatistics.Stores);
    }

    internal static void AssertFailure(DnssecResolutionResult result)
    {
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Equal(2, result.ResponseCode);
        Assert.Equal(0U, result.AuthenticatedTtl);
        Assert.Null(result.Origin);
        Assert.Null(result.UnsignedDelegation);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
    }
}
