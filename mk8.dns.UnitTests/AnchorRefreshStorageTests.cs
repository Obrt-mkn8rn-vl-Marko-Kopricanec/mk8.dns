using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRefreshStorageTests
{
    [Fact]
    public async Task ActualStoreKeepsDurableCheckpointIndependentOfUnsavedLegacyTrackerMutation()
    {
        using var f = new AnchorStorageFixture();
        using var store = f.Create();
        IDnssecAnchorCheckpointStore port = store;
        var before = port.ReadCommitted();
        var revoked = TrustAnchorFixture.Revoke(f.Keys.Key(f.Keys.A));
        Assert.True(TrustAnchorFixture.Apply(store.Tracker, [revoked], f.Keys.Sign([revoked], f.Keys.A, revoked)));
        Assert.Empty(store.Tracker.GetTrustAnchors());
        Assert.Equal(before.GetCheckpoint(), port.ReadCommitted().GetCheckpoint());
        var source = new StorageSource(f);
        var refresher = new DnssecAnchorRefresher(f.Keys.Origin, port, source, DnssecFixture.Verifier, AnchorRefreshFixture.Server, f.Keys.Clock);
        await using var refresherLifetime = refresher.ConfigureAwait(false);
        Assert.Single(refresher.Current.Anchors);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await refresher.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(2, store.Revision); Assert.Single(store.Tracker.GetTrustAnchors());
        store.Dispose();
        using var recovered = f.Open(2);
        Assert.Equal(2, recovered.Tracker.GetStatus().Count);
    }

    [Theory]
    [InlineData("origin")]
    [InlineData("revision")]
    [InlineData("cancellation")]
    public void CommitScopeAndAdmissionFailuresDoNotAlterAcknowledgedBytes(string kind)
    {
        using var f = new AnchorStorageFixture(); using var store = f.Create();
        IDnssecAnchorCheckpointStore port = store;
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        var candidate = string.Equals(kind, "origin", StringComparison.Ordinal)
            ? new DnssecTrustAnchorTracker(DnsName.Parse("other."), [new DnsRecord(DnsName.Parse("other."), 48, 0, f.Keys.Key(f.Keys.A).GetData())], DnssecFixture.Verifier)
            : f.Keys.Tracker(f.Keys.A);
        var before = f.Image();
        if (string.Equals(kind, "origin", StringComparison.Ordinal)) Assert.Throws<ArgumentException>(() => port.Commit(1, candidate, CancellationToken.None));
        else if (string.Equals(kind, "revision", StringComparison.Ordinal)) Assert.Throws<InvalidOperationException>(() => port.Commit(0, candidate, CancellationToken.None));
        else Assert.ThrowsAny<OperationCanceledException>(() => port.Commit(1, candidate, canceled.Token));
        Assert.Equal(before, f.Image()); Assert.Equal(1, port.ReadCommitted().Revision);
    }

    [Fact]
    public void ImmutableCheckpointOwnsValidatedBytesAndIndependentExportCopies()
    {
        using var f = new AnchorRefreshFixture(); var bytes = f.Store.State.GetCheckpoint();
        var state = new DnssecStoredAnchorCheckpoint(f.Keys.Origin, 7, bytes); var expected = state.GetCheckpoint();
        Array.Clear(bytes); var copy = state.GetCheckpoint(); Array.Clear(copy);
        Assert.Equal(expected, state.GetCheckpoint()); Assert.Equal(7, state.Revision);
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecStoredAnchorCheckpoint(f.Keys.Origin, 0, expected));
        Assert.Throws<FormatException>(() => new DnssecStoredAnchorCheckpoint(DnsName.Parse("other."), 1, expected));
        Assert.Throws<FormatException>(() => new DnssecStoredAnchorCheckpoint(f.Keys.Origin, 1, bytes));
    }

    [Fact]
    public void ReadCommittedReauthenticatesStorageAndRetainsFaultUntilRecovery()
    {
        using var f = new AnchorStorageFixture(); using var store = f.Create();
        IDnssecAnchorCheckpointStore port = store;
        var saved = File.ReadAllBytes(f.Head); var corrupt = (byte[])saved.Clone(); corrupt[^1] ^= 1;
        AnchorStorageFixture.Write(f.Head, corrupt);
        Assert.Throws<InvalidDataException>(() => port.ReadCommitted());
        AnchorStorageFixture.Write(f.Head, saved);
        Assert.Throws<IOException>(() => port.ReadCommitted());
        store.Dispose(); using var recovered = f.Open(); Assert.Equal(1, recovered.Revision);
    }

    private sealed class StorageSource(AnchorStorageFixture fixture) : IDnssecUpstream
    {
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            DnsRecord[] keys = [fixture.Keys.Key(fixture.Keys.A), fixture.Keys.Key(fixture.Keys.B)];
            return ValueTask.FromResult(new DnsUpstreamEvidence(question, server, 1, 0x8430, 0, hasEdns: true, 1232, 0, 0x8000,
                [.. keys, fixture.Keys.Sign(keys, fixture.Keys.A)], [], []));
        }
    }
}
