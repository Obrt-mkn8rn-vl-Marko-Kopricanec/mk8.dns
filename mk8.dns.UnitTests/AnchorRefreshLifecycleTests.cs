using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRefreshLifecycleTests
{
    [Fact]
    public async Task FreshObservationCommitsPendingThenPromotesOnlyAfterBothClocksAndAnotherAcquisition()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        var original = session.Current;
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(2, session.Current.Revision); Assert.Single(session.Current.Anchors);
        f.Keys.Clock.Advance(TimeSpan.FromDays(29).TotalSeconds);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Single(session.Current.Anchors);
        f.Keys.Clock.Advance(TimeSpan.FromDays(1).TotalSeconds);
        Assert.Single(session.Current.Anchors);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(4, session.Current.Revision); Assert.Equal(2, session.Current.Anchors.Count);
        Assert.Single(original.Anchors); Assert.Equal(1, original.Revision);
        Assert.Equal(3, f.Upstream.Calls); Assert.Equal(3, f.Store.Commits);
    }

    [Fact]
    public async Task RecoveryPausesHoldAndStillNeedsFreshProofAfterRebasedRemainingTime()
    {
        using var f = new AnchorRefreshFixture();
        await using (var session = f.Create())
        {
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
            f.Keys.Clock.Advance(TimeSpan.FromDays(10).TotalSeconds);
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        }
        f.Keys.Clock.Advance(TimeSpan.FromDays(90).TotalSeconds);
        await using var recovered = f.Create();
        Assert.Single(recovered.Current.Anchors);
        f.Keys.Clock.Advance(TimeSpan.FromDays(19).TotalSeconds);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await recovered.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Single(recovered.Current.Anchors);
        f.Keys.Clock.Advance(TimeSpan.FromDays(1).TotalSeconds);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await recovered.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(2, recovered.Current.Anchors.Count);
    }

    [Fact]
    public async Task AuthenticatedAbsenceResetsPendingAndDoesNotDiscardMissingAcceptedAnchor()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        f.Keys.Clock.Advance(TimeSpan.FromDays(30).TotalSeconds);
        f.Records = [f.Keys.Key(f.Keys.A)];
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        f.Records = [f.Keys.Key(f.Keys.A), f.Keys.Key(f.Keys.B)];
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Single(session.Current.Anchors);
        f.Records = [f.Keys.Key(f.Keys.B)]; f.Signatures = [f.Keys.Sign(f.Records, f.Keys.A)];
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(f.Keys.Key(f.Keys.A).GetData(), Assert.Single(session.Current.Anchors).Record.GetData());
    }

    [Fact]
    public async Task PermanentSelfRevocationIsCommittedBeforeEmptyTrustIsExposedAndSurvivesRecovery()
    {
        using var f = new AnchorRefreshFixture();
        await using (var session = f.Create())
        {
            var old = session.Current;
            f.Records = [TrustAnchorFixture.Revoke(f.Keys.Key(f.Keys.A))];
            f.Signatures = [f.Keys.Sign(f.Records, f.Keys.A, f.Records[0])];
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
            Assert.Equal(2, f.Store.State.Revision); Assert.Empty(session.Current.Anchors);
            Assert.Single(old.Anchors); // Old caller-owned profiles are not retroactively revoked.
        }
        await using var recovered = f.Create();
        Assert.Empty(recovered.Current.Anchors);
        f.Records = [f.Keys.Key(f.Keys.A)]; f.Signatures = null;
        Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await recovered.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(2, recovered.Current.Revision); Assert.Equal(1, f.Store.Commits);
    }

    [Fact]
    public async Task RepeatedSuccessfulRefreshDoesNotRebaseAwayTimeSpentBetweenObservations()
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        for (var day = 0; day < 30; day++)
        {
            f.Keys.Clock.Advance(TimeSpan.FromDays(1).TotalSeconds);
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        }
        Assert.Equal(2, session.Current.Anchors.Count); Assert.Equal(32, session.Current.Revision);
    }
}
