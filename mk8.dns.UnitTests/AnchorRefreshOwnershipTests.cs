using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorRefreshOwnershipTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HeldSourceRetainsAdmissionAndDisposalEvenWhenCallerCancels(bool cancel)
    {
        using var f = new AnchorRefreshFixture();
        using var caller = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Upstream.Override = (_, _, _) => { entered.SetResult(); return new(held.Task); };
        var session = f.Create();
        var refresh = session.RefreshAsync(caller.Token).AsTask();
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, f.Keys.Clock, caller.Token).ConfigureAwait(true);
        try
        {
            Assert.Equal(DnssecAnchorRefreshOutcome.Busy, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
            if (cancel) await caller.CancelAsync().ConfigureAwait(true);
            var closing = session.DisposeAsync().AsTask();
            Assert.Same(closing, session.DisposeAsync().AsTask());
            Assert.False(refresh.IsCompleted); Assert.False(closing.IsCompleted);
            Assert.Throws<ObjectDisposedException>(() => session.Current);
            await Assert.ThrowsAsync<ObjectDisposedException>(() => session.RefreshAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
            held.SetResult(f.Reply());
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => refresh.WaitAsync(AnchorRefreshFixture.Timeout, f.Keys.Clock, CancellationToken.None)).ConfigureAwait(true);
            else Assert.Equal(DnssecAnchorRefreshOutcome.Refused, await refresh.ConfigureAwait(true));
            await closing.WaitAsync(AnchorRefreshFixture.Timeout, f.Keys.Clock, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(0, f.Store.Commits); Assert.Equal(1, f.Upstream.Calls);
        }
        finally
        {
            held.TrySetResult(f.Reply());
            _ = await Record.ExceptionAsync(() => refresh.WaitAsync(AnchorRefreshFixture.Timeout, f.Keys.Clock, CancellationToken.None)).ConfigureAwait(true);
            await session.DisposeAsync().ConfigureAwait(true);
        }
    }

    [Fact]
    public async Task SnapshotIsNotPublishedDuringHeldCommitAndClosingJoinsActualStorage()
    {
        using var f = new AnchorRefreshFixture();
        using var resume = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Store.BeforeCommit = () => { entered.SetResult(); if (!resume.Wait(AnchorRefreshFixture.Timeout)) throw new TimeoutException(); };
        var session = f.Create(); var original = session.Current;
        var refresh = session.RefreshAsync(CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, f.Keys.Clock).ConfigureAwait(true);
            Assert.Same(original, session.Current); Assert.Equal(0, f.Store.Commits);
            Assert.Equal(DnssecAnchorRefreshOutcome.Busy, await session.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
            var closing = session.DisposeAsync().AsTask();
            Assert.False(refresh.IsCompleted); Assert.False(closing.IsCompleted);
            resume.Set();
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await refresh.WaitAsync(AnchorRefreshFixture.Timeout, f.Keys.Clock).ConfigureAwait(true));
            await closing.WaitAsync(AnchorRefreshFixture.Timeout, f.Keys.Clock).ConfigureAwait(true);
            Assert.Equal(2, f.Store.State.Revision); Assert.Single(original.Anchors);
        }
        finally
        {
            resume.Set(); _ = await Record.ExceptionAsync(() => refresh.WaitAsync(AnchorRefreshFixture.Timeout, f.Keys.Clock)).ConfigureAwait(true);
            await session.DisposeAsync().ConfigureAwait(true);
        }
    }

    [Fact]
    public async Task CancellationBeforeAdmissionAndDuringVerificationCannotCommit()
    {
        using var f = new AnchorRefreshFixture(); using var caller = new CancellationTokenSource();
        var verifier = new DnssecChainFixture.CountingVerifier { AfterVerify = caller.Cancel };
        await using var session = f.Create(verifier);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => session.RefreshAsync(caller.Token).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, f.Store.Commits); Assert.Equal(1, session.Current.Revision);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => session.RefreshAsync(caller.Token).AsTask()).ConfigureAwait(true);
        Assert.Equal(1, f.Upstream.Calls);
    }
}
