using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustEpochLifetimeTests
{
    [Fact]
    public async Task ZeroTtlOuterDeliveryCannotMaskAReusableExpiredBootstrapCacheEntry()
    {
        var fixture = await TrustEpochLifetimeFixture.CreateAsync(1, 1, monotonicOnly: false).ConfigureAwait(true);
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var original = await fixture.Resolver.ResolveDnssecAsync(fixture.Question, CancellationToken.None).ConfigureAwait(true);
        var next = await fixture.Resolver.ResolveDnssecAsync(fixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0u, original.AuthenticatedTtl);
        Assert.Equal(0u, next.AuthenticatedTtl);
        Assert.Equal(DnssecResolutionOutcome.Failure, original.Outcome); Assert.Equal(DnssecResolutionOutcome.Failure, next.Outcome);
        Assert.Empty(original.Answers); Assert.Empty(next.Answers);
        Assert.Equal(2, fixture.SourceCalls); Assert.Equal(2, fixture.BootstrapCalls); Assert.Equal(2, fixture.Verifier.Failures);
        Assert.Equal(0, fixture.Resolver.Statistics.Entries);
    }

    [Theory]
    [InlineData(1u, 300u, false)]
    [InlineData(300u, 1u, false)]
    [InlineData(1u, 1u, false)]
    [InlineData(1u, 300u, true)]
    [InlineData(300u, 1u, true)]
    [InlineData(1u, 1u, true)]
    public async Task FailedEarlierPinCannotRebaseExpiredReceivedKeysetOrSignatureLifetime(uint recordsTtl, uint signaturesTtl, bool monotonicOnly)
    {
        var fixture = await TrustEpochLifetimeFixture.CreateAsync(recordsTtl, signaturesTtl, monotonicOnly).ConfigureAwait(true);
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            var refused = await fixture.Resolver.ResolveDnssecAsync(fixture.Question, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Failure, refused.Outcome);
            Assert.Empty(refused.Answers); Assert.Empty(refused.Authority); Assert.Null(refused.UnsignedDelegation);
            Assert.Equal(0u, refused.AuthenticatedTtl); Assert.Equal(0, fixture.Resolver.Statistics.Entries);
            Assert.Equal(attempt, fixture.BootstrapCalls); Assert.Equal(attempt, fixture.SourceCalls);
            Assert.Equal(attempt, fixture.Verifier.Failures);
        }
        Assert.Equal(0, fixture.Resolver.Statistics.ActiveRequests); Assert.Equal(0, fixture.Resolver.Statistics.SourceRequests);
    }

    [Theory]
    [InlineData(5u, 300u, false)]
    [InlineData(300u, 5u, false)]
    [InlineData(5u, 5u, false)]
    [InlineData(5u, 300u, true)]
    [InlineData(300u, 5u, true)]
    [InlineData(5u, 5u, true)]
    public async Task LaterPinAndImmediateCacheReuseSpendEarlierVerifierTimeOnlyOnceAtAdmission(uint recordsTtl, uint signaturesTtl, bool monotonicOnly)
    {
        var fixture = await TrustEpochLifetimeFixture.CreateAsync(recordsTtl, signaturesTtl, monotonicOnly).ConfigureAwait(true);
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var original = await fixture.Resolver.ResolveDnssecAsync(fixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, original.Outcome);
        Assert.Equal(1u, original.AuthenticatedTtl); // The existing outer delivery policy conservatively spends source-await time again.
        Assert.Equal(1u, Assert.Single(original.Answers).Ttl);
        Assert.Equal(2, fixture.SourceCalls); Assert.Equal(1, fixture.BootstrapCalls); Assert.Equal(1, fixture.Verifier.Failures);
        var calls = fixture.Verifier.Calls;
        var hit = await fixture.Resolver.ResolveDnssecAsync(fixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, hit.Outcome);
        Assert.Equal(3u, hit.AuthenticatedTtl); Assert.Equal(3u, Assert.Single(hit.Answers).Ttl);
        Assert.Equal(calls, fixture.Verifier.Calls); Assert.Equal(2, fixture.SourceCalls);
        fixture.Advance(1);
        var aged = await fixture.Resolver.ResolveDnssecAsync(fixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2u, aged.AuthenticatedTtl); Assert.Equal(2u, Assert.Single(aged.Answers).Ttl);
        Assert.Equal(calls, fixture.Verifier.Calls); Assert.Equal(2, fixture.SourceCalls);
        fixture.Advance(2);
        var fresh = await fixture.Resolver.ResolveDnssecAsync(fixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome);
        Assert.Equal(2, fixture.BootstrapCalls); Assert.Equal(4, fixture.SourceCalls); Assert.Equal(2, fixture.Verifier.Failures);
        Assert.Equal(0, fixture.Resolver.Statistics.ActiveRequests); Assert.Equal(0, fixture.Resolver.Statistics.SourceRequests);
    }
}
