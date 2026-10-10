using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorPollingCommitTests
{
    [Fact]
    public async Task ClosingDuringAdmittedCommitPreservesSuccessfulAcknowledgementBeforeCompletion()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Source.Store.AfterCommit = () => { entered.TrySetResult(); if (!release.Wait(AnchorPollingFixture.Timeout)) throw new TimeoutException(); };
        var poller = fixture.Create(); await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        try
        {
            await entered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(2, fixture.Source.Store.State.Revision); Assert.Equal(1, fixture.Refresher.Current.Revision);
            var close = poller.DisposeAsync().AsTask(); Assert.False(close.IsCompleted); release.Set();
            await close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, poller.Statistics.Applied); Assert.Equal(2, fixture.Refresher.Current.Revision);
            Assert.Equal(1, fixture.Source.Upstream.Calls); Assert.True(poller.Statistics.Completed);
        }
        finally { release.Set(); }
    }

    [Fact]
    public async Task CancelledAmbiguousCommitFaultCannotBecomeHealthyStoppedCompletion()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Source.Store.BeforeCommit = () => { entered.TrySetResult(); if (!release.Wait(AnchorPollingFixture.Timeout)) throw new TimeoutException(); };
        var poller = fixture.Create(); fixture.ExpectFault(poller);
        await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        try
        {
            await entered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var close = poller.DisposeAsync().AsTask(); Assert.False(close.IsCompleted); release.Set();
            var error = await Assert.ThrowsAsync<AggregateException>(() => close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.Contains(error.InnerExceptions, exception => exception is OperationCanceledException);
            Assert.Contains(error.InnerExceptions, exception => exception is IOException);
            Assert.Throws<IOException>(() => fixture.Refresher.Current);
            Assert.Equal(0, fixture.Source.Store.Commits); Assert.Equal(0, poller.Statistics.Applied);
        }
        finally { release.Set(); }
    }

    [Fact]
    public async Task BorrowedBusyWorkIsSkippedCountedAndRemainsCallerOwnedDuringShutdown()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Source.Upstream.Override = (_, _, _) => { entered.TrySetResult(); return new(held.Task); };
        var external = fixture.Refresher.RefreshAsync(CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var poller = fixture.Create(maximumAttempts: 1); await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
            await poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, poller.Statistics.Busy); Assert.Equal(1, poller.Statistics.Attempts); Assert.False(external.IsCompleted);
            Assert.Equal(1, fixture.Source.Upstream.Calls); Assert.Equal(0, fixture.Source.Store.Commits);
        }
        finally { held.TrySetResult(fixture.Source.Reply()); await external.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
    }
}
