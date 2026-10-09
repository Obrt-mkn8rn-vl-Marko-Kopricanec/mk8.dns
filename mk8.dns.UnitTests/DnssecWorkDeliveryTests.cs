using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecWorkDeliveryTests
{
    [Theory]
    [InlineData("www.example.", 1, 0)]
    [InlineData("www.example.", 28, 0)]
    [InlineData("missing.example.", 1, 3)]
    [InlineData("www.child.example.", 1, 0)]
    public async Task CompleteAuthenticatedResultRemainsTypedAndCached(string name, int type, int code)
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var resolver = new CoalescingDnssecResolver(cache, new DnssecWorkPolicy());
        await using var resolverLifetime = resolver.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question(name, (ushort)type);
        var first = await resolver.ResolveDnssecAsync(question, CancellationToken.None).ConfigureAwait(true);
        var calls = fixture.Calls.Count;
        var second = await resolver.ResolveDnssecAsync(question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, first.Outcome);
        Assert.Equal(code, second.ResponseCode);
        Assert.Equal(first.Origin, second.Origin);
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(1, cache.Statistics.Hits);
        Assert.True(second.AuthenticatedTtl <= first.AuthenticatedTtl);
        Assert.False(typeof(Mk8.Dns.Domain.IDnsResolver).IsAssignableFrom(typeof(CoalescingDnssecResolver)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnauthenticatedFailureOrUnsignedMarkerIsNotPromotedOrPersisted(bool delegation)
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = delegation };
        if (!delegation) fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, answers: []);
        var cache = new CachingDnssecResolver(fixture.Resolver());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var resolver = new CoalescingDnssecResolver(cache, new DnssecWorkPolicy());
        await using var resolverLifetime = resolver.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question("www.child.example.");
        var result = await resolver.ResolveDnssecAsync(question, CancellationToken.None).ConfigureAwait(true);
        var calls = fixture.Calls.Count;
        Assert.Equal(delegation ? DnssecResolutionOutcome.UnsignedDelegation : DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.Equal(0, cache.Statistics.Entries);
        await resolver.ResolveDnssecAsync(question, CancellationToken.None).ConfigureAwait(true);
        Assert.True(fixture.Calls.Count > calls);
    }
}
