using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustEpochAnchorTests
{
    [Fact]
    public async Task EveryCommittedAnchorCanAuthenticateOneCompleteBootstrapRrset()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); await f.PromoteAsync().ConfigureAwait(true);
        Assert.Equal(2, f.Refresh.Current.Anchors.Count);
        var last = f.Refresh.Current.Anchors[^1].Record.GetData();
        var signer = last.AsSpan().SequenceEqual(f.Anchors.Keys.Key(f.Anchors.Keys.A).GetData()) ? f.Anchors.Keys.A : f.Anchors.Keys.B;
        f.KeySigner = signer; f.DataSigner = signer;
        var resolver = f.Create();
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(2, f.Calls.Count); Assert.Equal(2, resolver.Statistics.Anchors);
    }

    [Fact]
    public async Task UnrelatedIncludedKeyCannotAuthenticateTheKeyset()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); await f.PromoteAsync().ConfigureAwait(true);
        f.Anchors.Records = [.. f.Anchors.Records, f.Anchors.Keys.Key(f.Anchors.Keys.C)];
        f.KeySigner = f.Anchors.Keys.C;
        var resolver = f.Create();
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Single(f.Calls); Assert.InRange(f.Verifier.Calls, 0, 2); // A key-tag collision may consume a refused attempt.
    }

    [Fact]
    public async Task RevokedOldAnchorAndItsCachedDataAreNotReused()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); await f.PromoteAsync().ConfigureAwait(true);
        var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        await f.RevokeAsync().ConfigureAwait(true);
        Assert.Single(f.Refresh.Current.Anchors);
        f.Anchors.Records = [f.Anchors.Keys.Key(f.Anchors.Keys.A), f.Anchors.Keys.Key(f.Anchors.Keys.B)];
        var refused = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, refused.Outcome); Assert.Empty(refused.Answers);
        Assert.Equal(0, resolver.Statistics.Entries);
        f.KeySigner = f.Anchors.Keys.B; f.DataSigner = f.Anchors.Keys.B; f.LastOctet = 2;
        var recovered = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, Assert.Single(recovered.Answers).GetData()[3]); Assert.Equal(1, resolver.Statistics.Anchors);
    }

    [Fact]
    public async Task EmptyCommittedTrustRefusesWithoutBootstrapOrUnsignedFallback()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        await f.RevokeAsync().ConfigureAwait(true);
        Assert.Empty(f.Refresh.Current.Anchors);
        var calls = f.Calls.Count;
        var refused = await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, refused.Outcome);
        Assert.Empty(refused.Answers); Assert.Empty(refused.Authority); Assert.Null(refused.UnsignedDelegation);
        Assert.Equal(calls, f.Calls.Count); Assert.Equal(0, resolver.Statistics.OwnedProfiles);
    }

    [Fact]
    public async Task MultiplePinsDoNotRefundActualProviderVerificationBudget()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); await f.PromoteAsync().ConfigureAwait(true);
        var good = f.Anchors.Keys.Sign(f.Anchors.Records, f.Anchors.Keys.A);
        var bytes = good.GetData(); bytes[^1] ^= 1;
        f.Override = (question, server, _) => ValueTask.FromResult(f.Anchors.Reply(question, server,
            answers: [.. f.Anchors.Records, new(good.Owner, 46, good.Ttl, bytes), f.Anchors.Keys.Sign(f.Anchors.Records, f.Anchors.Keys.B)]));
        var resolver = f.Create(new DnssecTrustEpochPolicy(maximumVerificationAttempts: 1));
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(1, f.Verifier.Calls); Assert.Single(f.Calls);
    }
}
