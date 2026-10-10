using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AnchorPollingOwnershipTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task ClosingOwnsBlockedProviderAndActualCancellationCallbackInEitherCleanupOrder(bool providerFirst, bool callbackFault)
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        using var releaseCallback = new ManualResetEventSlim();
        var sourceEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken sourceToken = default; CancellationTokenRegistration registration = default;
        fixture.Source.Upstream.Override = (_, _, token) =>
        {
            sourceToken = token;
            registration = token.Register(() =>
            {
                callbackEntered.TrySetResult();
                if (!releaseCallback.Wait(AnchorPollingFixture.Timeout, CancellationToken.None)) throw new TimeoutException("Controlled callback gate did not release.");
                if (callbackFault) throw new InvalidOperationException("Controlled cancellation callback fault.");
            });
            sourceEntered.TrySetResult(); return new(held.Task);
        };
        var poller = fixture.Create(); if (callbackFault) fixture.ExpectFault(poller);
        await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        try
        {
            await sourceEntered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var close = poller.DisposeAsync().AsTask(); Assert.Same(close, poller.DisposeAsync().AsTask());
            Assert.True(sourceToken.IsCancellationRequested);
            await callbackEntered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.False(close.IsCompleted); Assert.False(poller.Completion.IsCompleted);
            await FinishHeldWorkAsync(fixture, poller, held, registration, releaseCallback, providerFirst, callbackFault).ConfigureAwait(true);
        }
        finally
        {
            releaseCallback.Set(); held.TrySetResult(fixture.Source.Reply());
            await registration.DisposeAsync().ConfigureAwait(true);
        }
    }

    private static async Task FinishHeldWorkAsync(AnchorPollingFixture fixture, Mk8.Dns.Engine.Recursive.DnssecAnchorPoller poller,
        TaskCompletionSource<DnsUpstreamEvidence> held, CancellationTokenRegistration registration, ManualResetEventSlim releaseCallback,
        bool providerFirst, bool callbackFault)
    {
        var close = poller.DisposeAsync().AsTask();
        if (providerFirst)
        {
            held.TrySetResult(fixture.Source.Reply());
        }
        else
        {
            releaseCallback.Set();
            await registration.DisposeAsync().ConfigureAwait(true);
        }
        Assert.False(close.IsCompleted); Assert.False(poller.Statistics.Completed);
        Assert.Equal(0, fixture.Source.Store.Commits); Assert.Equal(1, fixture.Refresher.Current.Revision);
        releaseCallback.Set(); held.TrySetResult(fixture.Source.Reply());
        if (callbackFault) await Assert.ThrowsAsync<AggregateException>(() => close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        else await close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.True(poller.Statistics.Completed); Assert.Equal(0, fixture.Clock.ActiveTimers);
        Assert.Equal(1, poller.Statistics.Attempts); Assert.Equal(0, fixture.Source.Store.Commits);
    }

    [Fact]
    public async Task CancellationDuringHeldTimerRetirementCannotReleaseLifetimeOrStartSource()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        fixture.Clock.HoldDisposal = true; var poller = fixture.Create();
        await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        await fixture.Clock.DisposalEntered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var close = poller.DisposeAsync().AsTask(); Assert.Same(close, poller.DisposeAsync().AsTask());
        Assert.False(close.IsCompleted); Assert.False(poller.Completion.IsCompleted); Assert.True(poller.Statistics.Waiting);
        Assert.Equal(0, fixture.Source.Upstream.Calls); Assert.Equal(1, fixture.Clock.ActiveTimers);
        fixture.Clock.DisposalReleased.TrySetResult();
        await close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, fixture.Clock.ActiveTimers); Assert.Equal(0, fixture.Source.Upstream.Calls);
        Assert.True(poller.Statistics.Completed); Assert.False(poller.Statistics.Waiting);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TimerCreationOrRetirementFailureFaultsCompletionAndLeavesNoSourceOrTimer(bool retirement)
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        fixture.Clock.FailCreation = !retirement; fixture.Clock.FailDisposal = retirement;
        var poller = fixture.Create(); fixture.ExpectFault(poller);
        if (retirement) { await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200); }
        await Assert.ThrowsAsync<IOException>(() => poller.Completion.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        await Assert.ThrowsAsync<IOException>(() => poller.DisposeAsync().AsTask().WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.True(poller.Statistics.Completed); Assert.Equal(0, fixture.Clock.ActiveTimers); Assert.Equal(0, fixture.Source.Upstream.Calls);
    }

    [Fact]
    public async Task SourceAndActualCallbackFaultsAreBothPreservedAfterOwnedCleanup()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationTokenRegistration registration = default;
        fixture.Source.Upstream.Override = (_, _, token) =>
        {
            registration = token.Register(() => throw new InvalidOperationException("Controlled callback fault."));
            entered.TrySetResult(); return new(held.Task);
        };
        var poller = fixture.Create(); fixture.ExpectFault(poller);
        await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        try
        {
            await entered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var close = poller.DisposeAsync().AsTask(); held.TrySetException(new InvalidOperationException("Controlled source fault."));
            var error = await Assert.ThrowsAsync<AggregateException>(() => close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.Contains(error.Flatten().InnerExceptions, value => value is InvalidOperationException && string.Equals(value.Message, "Controlled source fault.", StringComparison.Ordinal));
            Assert.Contains(error.Flatten().InnerExceptions, value => value is InvalidOperationException && string.Equals(value.Message, "Controlled callback fault.", StringComparison.Ordinal));
            Assert.True(poller.Statistics.Completed); Assert.Equal(0, fixture.Clock.ActiveTimers); Assert.Equal(0, fixture.Source.Store.Commits);
        }
        finally { held.TrySetException(new InvalidOperationException("Controlled source cleanup.")); await registration.DisposeAsync().ConfigureAwait(true); }
    }

    [Fact]
    public async Task HealthyOwnedAcquisitionCancellationStopsWithoutInventingCommitOrSourceFault()
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken owned = default;
        fixture.Source.Upstream.Override = (_, _, token) => { owned = token; entered.TrySetResult(); return new(held.Task); };
        var poller = fixture.Create(); await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        try
        {
            await entered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var close = poller.DisposeAsync().AsTask(); Assert.True(owned.IsCancellationRequested); Assert.False(close.IsCompleted);
            held.TrySetException(new OperationCanceledException(owned));
            await close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, fixture.Refresher.Current.Revision); Assert.Equal(0, fixture.Source.Store.Commits);
            Assert.Equal(1, poller.Statistics.Attempts); Assert.True(poller.Statistics.Completed); Assert.Equal(0, fixture.Clock.ActiveTimers);
        }
        finally { held.TrySetException(new OperationCanceledException(owned)); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnrelatedSourceFaultOrCancellationIsNotHiddenByConcurrentClose(bool cancellation)
    {
        var fixture = new AnchorPollingFixture(); await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Source.Upstream.Override = (_, _, _) => { entered.TrySetResult(); return new(held.Task); };
        var poller = fixture.Create(); fixture.ExpectFault(poller);
        await fixture.Clock.NextTimerAsync().ConfigureAwait(true); fixture.Clock.Set(7200);
        try
        {
            await entered.Task.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var close = poller.DisposeAsync().AsTask(); Assert.False(close.IsCompleted);
            held.TrySetException(cancellation ? new OperationCanceledException(CancellationToken.None) : new InvalidOperationException("Controlled source fault."));
            if (cancellation) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            else await Assert.ThrowsAsync<InvalidOperationException>(() => close.WaitAsync(AnchorPollingFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.True(poller.Statistics.Completed); Assert.Equal(0, fixture.Source.Store.Commits); Assert.Equal(1, fixture.Refresher.Current.Revision);
        }
        finally { held.TrySetException(new InvalidOperationException("Controlled source cleanup.")); }
    }
}
