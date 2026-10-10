using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofEpochCacheTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task FreshAndHitMaterialEncodeWithOriginalLeasesAndPolicy(bool coalesced, bool dnssecOk)
    {
        var f = new ClientProofEpochFixture(coalesced, policy: new DnssecTrustEpochPolicy(maximumPositiveTtl: 10, maximumNegativeTtl: 5));
        await using var lifetime = f.ConfigureAwait(true);
        var fresh = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(10U, fresh.AuthenticatedTtl);
        Assert.Single(ClientProofFixture.Proof(fresh).AnswerSignatures);
        var calls = f.Calls.Count; var crypto = f.Verifier.Calls;
        f.Advance(3);
        var hit = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(7U, hit.AuthenticatedTtl);
        var query = ClientMessageFixture.Query(dnssecOk: dnssecOk);
        Assert.True(DnssecClientMessageCodec.TryEncode(query, hit, tcp: true, recursionAvailable: true,
            authenticatedDataAllowed: true, out var packet));
        var decoded = ClientMessageFixture.Decode(packet, query);
        Assert.All(decoded.Answers, record => Assert.Equal(7U, record.Ttl));
        Assert.Equal(dnssecOk, (decoded.Flags & 32) != 0);
        Assert.Equal(calls, f.Calls.Count); Assert.Equal(crypto, f.Verifier.Calls);
        Assert.Equal(1, f.Resolver.Statistics.Entries); Assert.Equal(0, f.Timers.ActiveTimers);
        f.Advance(2);
        Assert.True(DnssecClientResponseProjection.TryPrepare(hit, f.Question, dnssecOk, out var queued));
        Assert.Equal(5U, queued.RemainingTtl);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IdenticalAcknowledgedPinsRetireAllCachedMaterial(bool coalesced)
    {
        var f = new ClientProofEpochFixture(coalesced); await using var lifetime = f.ConfigureAwait(true);
        var old = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        f.LastOctet = 2;
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        var fresh = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, Assert.Single(fresh.Answers).GetData()[3]);
        Assert.Single(ClientProofFixture.Proof(fresh).AnswerSignatures);
        Assert.Equal(4, f.Calls.Count); Assert.Equal(2, f.Resolver.Statistics.Revision);
        Assert.Equal(1, f.Resolver.Statistics.OwnedProfiles); Assert.Equal(0, f.Resolver.Statistics.RetiredProfiles);
        // Already returned values are historical; the facade cannot retro-revoke them.
        Assert.Equal(1, Assert.Single(old.Answers).GetData()[3]);
        f.Resolver.Clear();
        Assert.Equal(0, f.Resolver.Statistics.Entries);
        await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(6, f.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CandidateTtlBoundsCohortHitsAndQueuedDelivery(bool coalesced)
    {
        var f = new ClientProofEpochFixture(coalesced) { ShortCandidate = true }; await using var lifetime = f.ConfigureAwait(true);
        var first = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(3U, first.AuthenticatedTtl);
        f.Advance(0.01);
        var hit = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2U, hit.AuthenticatedTtl);
        Assert.Equal(2, ClientProofFixture.Proof(hit).AnswerSignatures.Count);
        f.Anchors.Keys.Clock.SetMonotonic(0); f.Anchors.Keys.Clock.SetWall(100);
        Assert.Equal(2U, (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).AuthenticatedTtl);
        Assert.Equal(2, f.Calls.Count);
        f.Advance(4);
        Assert.False(DnssecClientResponseProjection.TryPrepare(hit, f.Question, dnssecOk: true, out _));
        await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(4, f.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProofChargeCanRefuseStorageWithoutLosingFreshMaterial(bool coalesced)
    {
        var f = new ClientProofEpochFixture(coalesced, policy: new DnssecTrustEpochPolicy(maximumPayloadBytes: 150));
        await using var lifetime = f.ConfigureAwait(true);
        for (var index = 0; index < 2; index++)
            Assert.NotNull((await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).ClientProof);
        Assert.Equal(0, f.Resolver.Statistics.Entries); Assert.Equal(4, f.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ZeroLifetimeAuthenticatesWithoutReusableMaterial(bool coalesced)
    {
        var f = new ClientProofEpochFixture(coalesced) { DataTtl = 0 }; await using var lifetime = f.ConfigureAwait(true);
        for (var index = 0; index < 2; index++)
        {
            var result = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome); Assert.Equal(0U, result.AuthenticatedTtl);
            Assert.False(DnssecClientResponseProjection.TryPrepare(result, f.Question, dnssecOk: true, out _));
        }
        Assert.Equal(0, f.Resolver.Statistics.Entries); Assert.Equal(4, f.Calls.Count);
    }
}
