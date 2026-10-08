using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecCacheProofTests
{
    [Theory]
    [InlineData("www.example.", 28, false)]
    [InlineData("missing.example.", 1, false)]
    [InlineData("new.example.", 1, true)]
    [InlineData("new.child.example.", 1, true)]
    [InlineData("empty.example.", 1, false)]
    public async Task Nsec3ProofResultsCacheOnlyTheirExactQuestion(string name, int type, bool wildcard)
    {
        using var fixture = new OnlineNsec3Fixture { Wildcard = wildcard, Salt = [0xa1, 0xb2] };
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question(name, (ushort)type);
        var fresh = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var calls = fixture.Calls.Count;
        fixture.Clock.Advance(2);
        var cached = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome);
        Assert.Equal(fresh.ResponseCode, cached.ResponseCode);
        Assert.Equal(fresh.AuthenticatedTtl - 2, cached.AuthenticatedTtl);
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(1, cache.Statistics.Hits);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Nsec3UnsignedMarkerIsNotCachedEvenWhenOptOutAuthenticates(bool optOut)
    {
        using var fixture = new OnlineNsec3Fixture { Unsigned = true, OptOut = optOut };
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question("www.child.example.");
        for (var index = 0; index < 2; index++)
            Assert.Equal(DnssecResolutionOutcome.UnsignedDelegation, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        Assert.Equal(0, cache.Statistics.Entries);
        Assert.Equal(6, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DnskeyOrParentDsReceivedLifetimeBoundsWholeResult(bool parentDs)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => reply.Question.Type == (parentDs ? 43 : 48)
            ? OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Select(record => record.WithTtl(3)).ToArray()) : reply;
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question("www.child.example.");
        Assert.Equal(3U, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).AuthenticatedTtl);
        fixture.Clock.SetWall(103);
        var calls = fixture.Calls.Count;
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.True(fixture.Calls.Count > calls);
        Assert.Equal(1, cache.Statistics.Expirations);
    }

    [Fact]
    public async Task ParentDsSignatureWindowSpendsLeaseOnForwardWallJump()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type != 43) return reply;
            var ds = reply.Answers.Where(record => record.Type == 43).ToArray();
            return OnlineDnssecFixture.Copy(reply, answers: [.. ds, fixture.Sign(ds, window: new DnssecSignatureWindow(100, 103))]);
        };
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question("www.child.example.");
        Assert.Equal(3U, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).AuthenticatedTtl);
        fixture.Clock.SetWall(104);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Fact]
    public async Task AliasNegativeWholeAnswerUsesTerminalSoaAndShortestAlias()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("alias.example."), 5, 4, DnsName.Parse("missing.child.example.").ToWire()));
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question("alias.example.");
        var fresh = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(4U, fresh.AuthenticatedTtl);
        Assert.Equal(4U, Assert.Single(fresh.Answers).Ttl);
        Assert.Equal(fixture.Child, Assert.Single(fresh.Authority).Owner);
        Assert.Equal(4U, fresh.Authority[0].Ttl);
        fixture.Clock.Advance(1);
        Assert.Equal(3U, (await cache.ResolveDnssecAsync(question, CancellationToken.None)).AuthenticatedTtl);
    }

    [Fact]
    public async Task RrsetMinimumNormalizesEveryRecordOnFreshAndCachedDelivery()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Add(DnssecFixture.A(last: 2));
        fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Select(record =>
            record.Type == 1 && record.GetData()[3] == 2 ? record.WithTtl(11) : record).ToArray());
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        var fresh = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(2, fresh.Answers.Count);
        Assert.All(fresh.Answers, record => Assert.Equal(11U, record.Ttl));
        fixture.Clock.Advance(1);
        Assert.All((await cache.ResolveDnssecAsync(question, CancellationToken.None)).Answers, record => Assert.Equal(10U, record.Ttl));
    }
}
