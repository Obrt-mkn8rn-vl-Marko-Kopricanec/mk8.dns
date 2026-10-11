using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeClientHostLifetimeTests
{
    [Fact]
    public async Task ClosureBeforeRunAndRepeatedClosureKeepBorrowedInputsUsable()
    {
        var f = new NativeClientHostFixture(); await using var lifetime = f.ConfigureAwait(true);
        var host = await f.CreateAsync().ConfigureAwait(true);
        await Task.WhenAll(host.DisposeAsync().AsTask(), host.DisposeAsync().AsTask()).ConfigureAwait(true);
        Assert.Throws<ObjectDisposedException>((Action)(() => _ = host.RunAsync(CancellationToken.None)));
        Assert.Equal(1, f.Inputs.Refresh.Current.Revision); Assert.Empty(f.Inputs.Calls);
        Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers);
        Assert.Equal(0, f.Inputs.Timers.ActiveTimers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HostClosureJoinsDetachedIgnoredWorkerAndAllOwnedAdmissions(bool externalStop)
    {
        var f = new NativeClientHostFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync().ConfigureAwait(true);
        var running = host.RunAsync(deadline.Token);
        var endpoint = await host.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Inputs.Anchors.Keys.Origin, 48, 1);
        f.Inputs.Override = (question, server, _) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Inputs.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        try
        {
            using var peer = new UdpClient(endpoint.AddressFamily); peer.Connect(endpoint);
            _ = await peer.SendAsync(ClientRequestFixture.Request(), deadline.Token).ConfigureAwait(true);
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, host.ActiveWorkers);
            if (externalStop) await deadline.CancelAsync().ConfigureAwait(true);
            var first = host.DisposeAsync().AsTask(); var repeated = host.DisposeAsync().AsTask();
            await CoalescedTrustEpochFixture.WaitUntilAsync(() => host.ActiveRequests == 0).ConfigureAwait(true);
            Assert.False(first.IsCompleted); Assert.False(repeated.IsCompleted); Assert.False(running.IsCompleted);
            Assert.Equal(1, host.ActiveWorkers);
            held.TrySetResult(f.Inputs.Default(keys, AnchorRefreshFixture.Server));
            await Task.WhenAll(first, repeated, running).WaitAsync(AnchorRefreshFixture.Timeout,
                TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(0, host.ActiveWorkers); Assert.Equal(0, host.ActiveTcpConnections);
            Assert.Equal(0, f.Inputs.Timers.ActiveTimers); Assert.Equal(1, f.Inputs.Refresh.Current.Revision);
            Assert.Equal(externalStop, deadline.IsCancellationRequested);
        }
        finally { held.TrySetResult(f.Inputs.Default(keys, AnchorRefreshFixture.Server)); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task AutomaticFailureCleanupAndRepeatedDisposalPreserveBorrowedCancellation(bool tcp, bool clock)
    {
        var f = new NativeClientHostFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var host = await f.CreateAsync().ConfigureAwait(true); var running = host.RunAsync(deadline.Token);
        var endpoint = await host.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        var fault = new OperationCanceledException("Controlled host borrowed cancellation.", deadline.Token);
        f.ExpectedFailure = fault;
        if (clock) f.Inputs.Clock.BeforeTimestamp = _ => throw fault;
        else f.Inputs.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(fault);
        try
        {
            await SendAsync(endpoint, tcp, deadline.Token).ConfigureAwait(true);
            var observed = await Assert.ThrowsAnyAsync<Exception>(() => running.WaitAsync(AnchorRefreshFixture.Timeout,
                TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.True(NativeClientListenerFixture.OnlyExpected(observed, fault)); Assert.False(running.IsCompletedSuccessfully);
            foreach (var closing in new[] { host.DisposeAsync().AsTask(), host.DisposeAsync().AsTask() })
            {
                var error = await Assert.ThrowsAnyAsync<Exception>(() => closing.WaitAsync(AnchorRefreshFixture.Timeout,
                    TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
                Assert.True(NativeClientListenerFixture.OnlyExpected(error, fault)); Assert.False(closing.IsCompletedSuccessfully);
            }
            Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers);
            Assert.Equal(0, host.ActiveTcpConnections); Assert.Equal(0, f.Inputs.Timers.ActiveTimers);
            Assert.False(deadline.IsCancellationRequested); Assert.Equal(1, f.Inputs.Refresh.Current.Revision);
        }
        finally { f.Inputs.Clock.BeforeTimestamp = null; }
    }

    private static async Task SendAsync(IPEndPoint endpoint, bool tcp, CancellationToken token)
    {
        var packet = ClientRequestFixture.Request();
        if (!tcp)
        {
            using var peer = new UdpClient(endpoint.AddressFamily); peer.Connect(endpoint);
            _ = await peer.SendAsync(packet, token).ConfigureAwait(true); return;
        }
        using var peerTcp = new TcpClient(endpoint.AddressFamily); await peerTcp.ConnectAsync(endpoint, token).ConfigureAwait(true);
        var stream = peerTcp.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        await stream.WriteAsync(TcpSessionFixture.Frame(packet), token).ConfigureAwait(true);
        try { _ = await stream.ReadAsync(new byte[1], token).ConfigureAwait(true); }
        catch (IOException) { }
    }
}
