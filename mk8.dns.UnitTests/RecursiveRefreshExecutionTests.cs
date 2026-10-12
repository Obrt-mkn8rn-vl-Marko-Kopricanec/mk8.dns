using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecursiveRefreshExecutionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FiniteAppliedOrRefusedAttemptClosesServingAndRetainsBorrowedRefresher(bool refuse)
    {
        var f = new RecursiveRefreshFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var guard = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync().ConfigureAwait(true);
        var clock = new AnchorPollingFixture.ClockProvider(f.Inputs.Anchors.Keys.Clock);
        if (refuse) f.Inputs.Anchors.Upstream.Override = (_, _, _) => ValueTask.FromResult(f.Inputs.Anchors.Reply(flags: 0x8432));
        var running = f.RunAsync(host, f.Inputs.Refresh, Policy(), clock, guard.Token);
        _ = await host.WaitForBoundAsync(guard.Token).ConfigureAwait(true);
        Assert.Equal(TimeSpan.FromHours(1), await clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(0, f.Inputs.Anchors.Upstream.Calls); Assert.False(running.IsCompleted);
        clock.Set(3600);
        await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, f.Inputs.Anchors.Upstream.Calls);
        Assert.Equal(refuse ? 1 : 2, f.Inputs.Refresh.Current.Revision);
        Assert.Equal(refuse ? 0 : 1, f.Inputs.Anchors.Store.Commits);
        Assert.Equal(0, clock.ActiveTimers); Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers);
        Assert.Equal(0, host.ActiveTcpConnections); Assert.False(guard.IsCancellationRequested);
        await Task.WhenAll(host.DisposeAsync().AsTask(), host.DisposeAsync().AsTask()).ConfigureAwait(true);
        clock.Set(7200); Assert.Equal(1, f.Inputs.Anchors.Upstream.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StopJoinsHeldRefreshBeforeBorrowedStateCanClose(bool acknowledged)
    {
        var f = new RecursiveRefreshFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var guard = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync().ConfigureAwait(true);
        var clock = new AnchorPollingFixture.ClockProvider(f.Inputs.Anchors.Keys.Clock);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var acknowledgedStop = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Inputs.Anchors.Upstream.Override = (_, _, _) => { entered.TrySetResult(); return new(held.Task); };
        var running = f.RunAsync(host, f.Inputs.Refresh, Policy(), clock, guard.Token);
        try
        {
            _ = await host.WaitForBoundAsync(guard.Token).ConfigureAwait(true);
            _ = await clock.NextTimerAsync().ConfigureAwait(true); clock.Set(3600);
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            if (acknowledged)
            {
                f.Inputs.Anchors.Store.AfterCommit = () => acknowledgedStop.TrySetResult(host.DisposeAsync().AsTask());
                held.TrySetResult(f.Inputs.Anchors.Reply());
            }
            else
            {
                await guard.CancelAsync().ConfigureAwait(true);
                await host.DisposeAsync().ConfigureAwait(true);
                Assert.False(running.IsCompleted); Assert.Equal(1, f.Inputs.Refresh.Current.Revision);
                held.TrySetResult(f.Inputs.Anchors.Reply());
            }
            await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            if (acknowledged)
            {
                var closing = await acknowledgedStop.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
                await closing.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            }
            Assert.Equal(acknowledged ? 2 : 1, f.Inputs.Refresh.Current.Revision);
            Assert.Equal(0, clock.ActiveTimers); Assert.Equal(0, host.ActiveWorkers); Assert.Equal(0, host.ActiveRequests);
        }
        finally { held.TrySetResult(f.Inputs.Anchors.Reply()); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnsolicitedRefreshFaultStopsHostAndPreservesOriginalNonSuccess(bool canceled)
    {
        var f = new RecursiveRefreshFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var guard = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync().ConfigureAwait(true);
        var clock = new AnchorPollingFixture.ClockProvider(f.Inputs.Anchors.Keys.Clock);
        Exception fault = canceled ? new OperationCanceledException("Controlled refresh cancellation.", guard.Token)
            : new InvalidOperationException("Controlled refresh provider fault.");
        f.ExpectedRunFailure = fault;
        f.Inputs.Anchors.Upstream.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(fault);
        var running = f.RunAsync(host, f.Inputs.Refresh, Policy(), clock, guard.Token);
        _ = await host.WaitForBoundAsync(guard.Token).ConfigureAwait(true);
        _ = await clock.NextTimerAsync().ConfigureAwait(true); clock.Set(3600);
        var error = await Assert.ThrowsAnyAsync<Exception>(() => running.WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.True(NativeClientListenerFixture.OnlyExpected(error, fault)); Assert.False(running.IsCompletedSuccessfully);
        Assert.False(guard.IsCancellationRequested); Assert.Equal(1, f.Inputs.Refresh.Current.Revision);
        Assert.Equal(0, clock.ActiveTimers); Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers);
        await Task.WhenAll(host.DisposeAsync().AsTask(), host.DisposeAsync().AsTask()).ConfigureAwait(true);
    }

    [Fact]
    public async Task TimerCreationFailureStillClosesAcquiredHost()
    {
        var f = new RecursiveRefreshFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var guard = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync().ConfigureAwait(true);
        var clock = new AnchorPollingFixture.ClockProvider(f.Inputs.Anchors.Keys.Clock) { FailCreation = true };
        var running = f.RunAsync(host, f.Inputs.Refresh, Policy(), clock, guard.Token);
        var error = await Assert.ThrowsAnyAsync<Exception>(() => running.WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        var leaves = error is AggregateException aggregate ? aggregate.Flatten().InnerExceptions.ToArray() : [error];
        Assert.All(leaves, leaf => Assert.IsType<IOException>(leaf));
        f.ExpectedRunFailure = leaves[0];
        Assert.Equal(0, f.Inputs.Anchors.Upstream.Calls); Assert.Equal(0, clock.ActiveTimers);
        Assert.Equal(0, host.ActiveRequests); Assert.Equal(1, f.Inputs.Refresh.Current.Revision);
    }

    [Fact]
    public async Task PreCanceledExecutionClosesHostWithoutBorrowedAcquisition()
    {
        var f = new RecursiveRefreshFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var stop = new CancellationTokenSource(); await stop.CancelAsync().ConfigureAwait(true);
        f.ExpectedCancellation = stop.Token;
        var host = await f.CreateAsync().ConfigureAwait(true);
        var clock = new AnchorPollingFixture.ClockProvider(f.Inputs.Anchors.Keys.Clock);
        var running = f.RunAsync(host, f.Inputs.Refresh, Policy(), clock, stop.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running.WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, f.Inputs.Anchors.Upstream.Calls); Assert.Equal(0, clock.ActiveTimers);
        await host.DisposeAsync().ConfigureAwait(true); Assert.Equal(1, f.Inputs.Refresh.Current.Revision);
    }

    private static DnssecAnchorPollingPolicy Policy() => new(TimeSpan.FromHours(1), TimeSpan.FromHours(1), 1);

    [Fact]
    public async Task SignalStartsPollerStopWhileDetachedClientProviderStillHoldsHostClosure()
    {
        var f = new RecursiveRefreshFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var guard = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        using var stop = new CancellationTokenSource();
        var host = await f.CreateAsync().ConfigureAwait(true);
        var clock = new AnchorPollingFixture.ClockProvider(f.Inputs.Anchors.Keys.Clock);
        var keys = new Mk8.Dns.Domain.DnsQuestion(f.Inputs.Anchors.Keys.Origin, 48, 1);
        var client = f.Inputs.Hold(keys);
        var enteredClient = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var enteredRefresh = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var refresh = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken refreshToken = default;
        f.Inputs.Override = (_, _, _) => { enteredClient.TrySetResult(); return new(client.Task); };
        f.Inputs.Anchors.Upstream.Override = (_, _, token) => { refreshToken = token; enteredRefresh.TrySetResult(); return new(refresh.Task); };
        var running = f.RunAsync(host, f.Inputs.Refresh, Policy(), clock, stop.Token);
        try
        {
            var endpoint = await host.WaitForBoundAsync(guard.Token).ConfigureAwait(true);
            _ = await clock.NextTimerAsync().ConfigureAwait(true);
            using var peer = new System.Net.Sockets.UdpClient(endpoint.AddressFamily); peer.Connect(endpoint);
            _ = await peer.SendAsync(ClientRequestFixture.Request(), guard.Token).ConfigureAwait(true);
            await enteredClient.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            clock.Set(3600);
            await enteredRefresh.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await stop.CancelAsync().ConfigureAwait(true);
            await CoalescedTrustEpochFixture.WaitUntilAsync(() => refreshToken.IsCancellationRequested).ConfigureAwait(true);
            Assert.False(running.IsCompleted); Assert.Equal(1, host.ActiveWorkers);
            refresh.TrySetResult(f.Inputs.Anchors.Reply());
            client.TrySetResult(f.Inputs.Default(keys, AnchorRefreshFixture.Server));
            await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            AssertJoined(host, clock, f.Inputs.Refresh);
        }
        finally
        {
            refresh.TrySetResult(f.Inputs.Anchors.Reply());
            client.TrySetResult(f.Inputs.Default(keys, AnchorRefreshFixture.Server));
        }
    }

    private static void AssertJoined(DnssecClientHost host, AnchorPollingFixture.ClockProvider clock, DnssecAnchorRefresher refresher)
    {
        Assert.Equal(0, host.ActiveWorkers); Assert.Equal(0, clock.ActiveTimers); Assert.Equal(1, refresher.Current.Revision);
    }
}
