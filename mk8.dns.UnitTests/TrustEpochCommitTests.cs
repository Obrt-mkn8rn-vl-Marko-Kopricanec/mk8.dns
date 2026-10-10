using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TrustEpochCommitTests
{
    [Fact]
    public async Task RefusedRefreshDoesNotReplaceAUsableEpoch()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        f.Anchors.Signatures = [f.Anchors.Keys.Sign(f.Anchors.Records, f.Anchors.Keys.B)];
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, f.Calls.Count); Assert.Equal(1, resolver.Statistics.Revision);
    }

    [Fact]
    public async Task RefreshStillAwaitingAcquisitionDoesNotPublishPrivateCandidateState()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Anchors.Upstream.Override = (_, _, _) => { entered.SetResult(); return new(held.Task); };
        var refresh = f.Refresh.RefreshAsync(CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout).ConfigureAwait(true);
            Assert.Equal(DnssecAnchorRefreshOutcome.Busy, await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
            await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(2, f.Calls.Count); Assert.Equal(1, resolver.Statistics.Revision);
        }
        finally { held.TrySetResult(f.Anchors.Reply()); }
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await refresh.WaitAsync(AnchorRefreshFixture.Timeout).ConfigureAwait(true));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LostOrWrongCommitAcknowledgementPreventsOldTrustDelivery(bool wrongRevision)
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        if (wrongRevision) f.Anchors.Store.ReplyRevision = 3;
        else f.Anchors.Store.AfterCommit = () => throw new IOException("Controlled lost acknowledgement.");
        if (wrongRevision)
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Refresh.RefreshAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        else await Assert.ThrowsAsync<IOException>(() => f.Refresh.RefreshAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        await Assert.ThrowsAsync<IOException>(() => resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(2, f.Calls.Count); Assert.Equal(0, resolver.Statistics.Entries);
        await Assert.ThrowsAsync<IOException>(() => resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        await resolver.DisposeAsync().ConfigureAwait(true);
        Assert.Equal(0, resolver.Statistics.OwnedProfiles);
    }

    [Fact]
    public async Task ClosingTheCallerRefresherCannotLeaveAnOldCacheUsable()
    {
        var f = new TrustEpochFixture(); await using var fixtureLifetime = f.ConfigureAwait(true); var resolver = f.Create();
        await resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        await f.Refresh.DisposeAsync().ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, resolver.Statistics.Entries); Assert.Equal(2, f.Calls.Count);
        await resolver.DisposeAsync().ConfigureAwait(true);
    }
}
