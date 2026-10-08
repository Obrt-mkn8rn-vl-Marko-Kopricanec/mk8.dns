using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecCacheResolutionTests
{
    [Theory]
    [InlineData("www.example.", 1, 0, 2)]
    [InlineData("www.example.", 28, 0, 2)]
    [InlineData("missing.example.", 1, 3, 2)]
    [InlineData("www.child.example.", 1, 0, 5)]
    [InlineData("missing.child.example.", 1, 3, 5)]
    [InlineData("child.example.", 43, 0, 2)]
    public async Task CompletedAuthenticatedAnswersAvoidNetworkAndCrypto(string name, int type, int code, int calls)
    {
        using var fixture = new OnlineDnssecFixture();
        var verifier = new DnssecChainFixture.CountingVerifier();
        var cache = new CachingDnssecResolver(fixture.Resolver(verifier: verifier));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = Question(name, (ushort)type);
        var fresh = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var verifications = verifier.Calls;
        var cached = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome);
        Assert.Equal(code, cached.ResponseCode);
        Assert.Equal(fresh.Origin, cached.Origin);
        Assert.Equal(Bytes(fresh.Answers), Bytes(cached.Answers));
        Assert.Equal(Bytes(fresh.Authority), Bytes(cached.Authority));
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(verifications, verifier.Calls);
        Assert.Equal(1, cache.Statistics.Hits);
        Assert.Equal(1, cache.Statistics.Entries);
    }

    [Fact]
    public async Task ExactTypeAndClassKeysDoNotReuseNameErrorOrOtherType()
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var name = "missing.example.";
        Assert.Equal(3, (await cache.ResolveDnssecAsync(Question(name), CancellationToken.None)).ResponseCode);
        Assert.Equal(3, (await cache.ResolveDnssecAsync(Question(name, 28), CancellationToken.None)).ResponseCode);
        Assert.Equal(4, fixture.Calls.Count);
        Assert.Equal(DnssecResolutionOutcome.Failure,
            (await cache.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse(name), 1, 3), CancellationToken.None)).Outcome);
        Assert.Equal(0, cache.Statistics.Hits);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailureAndUnsignedDelegationNeverEnterCache(bool delegation)
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = delegation };
        if (!delegation) fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, answers: []);
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = Question("www.child.example.");
        var first = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var calls = fixture.Calls.Count;
        var second = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(delegation ? DnssecResolutionOutcome.UnsignedDelegation : DnssecResolutionOutcome.Failure, first.Outcome);
        Assert.Equal(first.Outcome, second.Outcome);
        Assert.Empty(second.Answers);
        Assert.Empty(second.Authority);
        Assert.Equal(calls * 2, fixture.Calls.Count);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Fact]
    public async Task CacheRemainsBoundToOneStaticTrustProfile()
    {
        using var first = new OnlineDnssecFixture();
        using var second = new OnlineDnssecFixture();
        second.RootRecords[0] = DnssecFixture.A(last: 99);
        var left = new CachingDnssecResolver(first.Resolver());
        await using var leftLifetime = left.ConfigureAwait(true);
        var right = new CachingDnssecResolver(second.Resolver());
        await using var rightLifetime = right.ConfigureAwait(true);
        var question = Question();
        var leftResult = await left.ResolveDnssecAsync(question, CancellationToken.None);
        var rightResult = await right.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(1, Assert.Single(leftResult.Answers).GetData()[3]);
        Assert.Equal(99, Assert.Single(rightResult.Answers).GetData()[3]);
        Assert.Equal(2, first.Calls.Count);
        Assert.Equal(2, second.Calls.Count);
        Assert.False(typeof(IDnsResolver).IsAssignableFrom(typeof(CachingDnssecResolver)));
    }

    [Fact]
    public async Task DnameWholeChainIsRetainedWithoutInlineInfrastructure()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        var cache = new CachingDnssecResolver(fixture.Zones.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var fresh = await cache.ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        var calls = fixture.Zones.Calls.Count;
        var cached = await cache.ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome);
        Assert.Equal(new ushort[] { 39, 5, 1 }, cached.Answers.Select(record => record.Type));
        Assert.Empty(cached.Authority);
        Assert.Equal(calls, fixture.Zones.Calls.Count);
    }

    [Fact]
    public async Task ExternalNameserverRoutingProofCapsCacheWithoutLeakingRecords()
    {
        using var fixture = new NameserverDnssecFixture { AddressTtl = 7 };
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var fresh = await cache.ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        var calls = fixture.Calls.Count;
        fixture.Clock.Advance(2);
        var cached = await cache.ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(7U, fresh.AuthenticatedTtl);
        Assert.Equal(5U, cached.AuthenticatedTtl);
        Assert.Equal(5U, Assert.Single(cached.Answers).Ttl);
        Assert.Equal(NameserverDnssecFixture.Question.Name, cached.Answers[0].Owner);
        Assert.Equal(calls, fixture.Calls.Count);
    }

    internal static DnsQuestion Question(string name = "www.example.", ushort type = 1) => new(DnsName.Parse(name), type, 1);
    private static string[] Bytes(IReadOnlyList<DnsRecord> records)
        => records.Select(record => record.Owner + ":" + record.Type + ":" + record.Ttl + ":" + Convert.ToHexString(record.GetData())).ToArray();
}
