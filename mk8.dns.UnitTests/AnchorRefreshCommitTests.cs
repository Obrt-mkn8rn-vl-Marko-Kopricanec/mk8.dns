using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRefreshCommitTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnyCommitExceptionFaultsAdoptionUntilExplicitRecovery(bool afterCommit)
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        var old = session.Current;
        if (afterCommit) f.Store.AfterCommit = () => throw new IOException("Controlled ambiguous acknowledgement.");
        else f.Store.BeforeCommit = () => throw new IOException("Controlled commit refusal.");
        await Assert.ThrowsAsync<IOException>(() => session.RefreshAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Throws<IOException>(() => session.Current);
        await Assert.ThrowsAsync<IOException>(() => session.RefreshAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Single(old.Anchors); Assert.Equal(afterCommit ? 2 : 1, f.Store.State.Revision);
        f.Store.BeforeCommit = null; f.Store.AfterCommit = null;
        await using var recovered = f.Create();
        Assert.Equal(f.Store.State.Revision, recovered.Current.Revision);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await recovered.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public async Task WrongAcknowledgementRevisionCannotPublishProspectiveTrust(long acknowledgement)
    {
        using var f = new AnchorRefreshFixture(); await using var session = f.Create();
        f.Store.ReplyRevision = acknowledgement;
        await Assert.ThrowsAsync<InvalidDataException>(() => session.RefreshAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Throws<IOException>(() => session.Current); Assert.Equal(2, f.Store.State.Revision);
    }

    [Fact]
    public async Task CancellationThrownByCommitPortFaultsAmbiguousAdoption()
    {
        using var f = new AnchorRefreshFixture(); using var caller = new CancellationTokenSource();
        await using var session = f.Create();
        f.Store.AfterCommit = () => { caller.Cancel(); caller.Token.ThrowIfCancellationRequested(); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => session.RefreshAsync(caller.Token).AsTask()).ConfigureAwait(true);
        Assert.Equal(2, f.Store.State.Revision); Assert.Throws<IOException>(() => session.Current);
    }
}
