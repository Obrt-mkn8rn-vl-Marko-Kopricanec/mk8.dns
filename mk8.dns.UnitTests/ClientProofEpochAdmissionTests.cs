using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofEpochAdmissionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailureHoldDownIsRejectedBeforeAnyBorrowedWork(bool coalesced)
    {
        using var anchors = new AnchorRefreshFixture();
        var refresh = anchors.Create(); await using var lifetime = refresh.ConfigureAwait(true);
        var policy = new DnssecTrustEpochPolicy(failureCache: new DnssecFailureCachePolicy());
        var timers = new RecursiveCacheClock();
        var error = Assert.Throws<ArgumentException>(() => coalesced
            ? DnssecTrustEpochResolver.CreateWithClientProofAndCoalescing(refresh, anchors.Upstream,
                DnssecFixture.Verifier, [AnchorRefreshFixture.Server], policy, new DnssecWorkPolicy(), timers)
            : DnssecTrustEpochResolver.CreateWithClientProof(refresh, anchors.Upstream,
                DnssecFixture.Verifier, [AnchorRefreshFixture.Server], policy));
        Assert.Equal("policy", error.ParamName);
        Assert.Equal(0, anchors.Upstream.Calls); Assert.Equal(0, anchors.Store.Commits);
        Assert.Equal(0, timers.ActiveTimers); Assert.Equal(1, refresh.Current.Revision);
    }

    [Fact]
    public async Task OptInDoesNotMutateTheCallersPolicyOrLegacyConstructor()
    {
        var policy = new DnssecTrustEpochPolicy();
        var f = new ClientProofEpochFixture(policy: policy); await using var lifetime = f.ConfigureAwait(true);
        Assert.NotNull((await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).ClientProof);
        var legacy = new DnssecTrustEpochResolver(f.Refresh, f.Anchors.Upstream, DnssecFixture.Verifier,
            [AnchorRefreshFixture.Server], policy);
        await using var legacyLifetime = legacy.ConfigureAwait(true);
        var keys = new Mk8.Dns.Domain.DnsQuestion(f.Anchors.Keys.Origin, 48, 1);
        var result = await legacy.ResolveDnssecAsync(keys, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome); Assert.Null(result.ClientProof);
    }
}
