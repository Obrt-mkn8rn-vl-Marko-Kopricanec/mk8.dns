using System.Net.Sockets;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeClientListenerLifetimeTests
{
    [Fact]
    public async Task ClosingJoinsActualIgnoredProviderAndKeepsBorrowedProcessorUsable()
    {
        var f = new NativeClientListenerFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var endpoint = await f.StartAsync(deadline.Token).ConfigureAwait(true);
        var keys = new DnsQuestion(f.Epoch.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Epoch.Override = (question, server, _) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Epoch.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        var response = NativeClientListenerFixture.UdpAsync(endpoint, ClientRequestFixture.Request(), deadline.Token);
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        var first = f.Listener.DisposeAsync().AsTask(); var second = f.Listener.DisposeAsync().AsTask();
        Assert.False(first.IsCompleted); Assert.False(second.IsCompleted); Assert.Equal(1, f.Processor.ActiveRequests);
        held.TrySetResult(f.Epoch.Default(keys, AnchorRefreshFixture.Server));
        await Task.WhenAll(first, second).WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        await deadline.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => response.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, f.Processor.ActiveRequests);
        var result = await f.Processor.ProcessAsync(ClientRequestFixture.Request(), f.Address.GetAddressBytes(), tcp: false,
            CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(Mk8.Dns.Engine.Recursive.DnssecClientReplyOutcome.Encoded, result.Outcome);
    }

    [Fact]
    public async Task DetachedCoalescedProviderRemainsOwnedByBorrowedEpochAfterListenerClosure()
    {
        var f = new NativeClientListenerFixture(coalesced: true); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var endpoint = await f.StartAsync(deadline.Token).ConfigureAwait(true);
        var keys = new DnsQuestion(f.Epoch.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Epoch.Override = (question, server, _) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Epoch.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        var response = NativeClientListenerFixture.UdpAsync(endpoint, ClientRequestFixture.Request(), deadline.Token);
        await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        await f.Listener.DisposeAsync().AsTask().WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, f.Processor.ActiveRequests); Assert.Equal(1, f.Epoch.Resolver.ActiveWorkers);
        var epochClosure = f.Epoch.Resolver.DisposeAsync().AsTask(); Assert.False(epochClosure.IsCompleted);
        held.TrySetResult(f.Epoch.Default(keys, AnchorRefreshFixture.Server));
        await epochClosure.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        await deadline.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => response.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.Equal(0, f.Epoch.Resolver.ActiveWorkers);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task BorrowedClockIoOrProviderFaultIsNotPeerDisconnect(bool tcp, bool clockFault)
    {
        var f = new NativeClientListenerFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var endpoint = await f.StartAsync(deadline.Token).ConfigureAwait(true);
        Exception fault = clockFault ? new IOException("Controlled borrowed clock fault.")
            : new InvalidOperationException("Controlled provider state failure.");
        f.ExpectedFailure = fault;
        if (clockFault) f.Epoch.Clock.BeforeTimestamp = _ => throw fault;
        else f.Epoch.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(fault);
        await SendAsync(f, endpoint, tcp, deadline.Token).ConfigureAwait(true);
        Assert.NotNull(f.Running);
        var observed = await Assert.ThrowsAnyAsync<Exception>(() => f.Running.WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        Assert.True(NativeClientListenerFixture.OnlyExpected(observed, fault));
        var repeated = await Assert.ThrowsAnyAsync<Exception>(() => f.Listener.DisposeAsync().AsTask()).ConfigureAwait(true);
        Assert.True(NativeClientListenerFixture.OnlyExpected(repeated, fault));
        Assert.Equal(0, f.Listener.ActiveTcpConnections); Assert.Equal(0, f.Processor.ActiveRequests);
    }

    private static async Task SendAsync(NativeClientListenerFixture f, System.Net.IPEndPoint endpoint, bool tcp, CancellationToken token)
    {
        var request = ClientRequestFixture.Request();
        if (!tcp)
        {
            using var peer = new UdpClient(f.Address.AddressFamily); peer.Connect(endpoint);
            _ = await peer.SendAsync(request, token).ConfigureAwait(true); return;
        }
        using var client = new TcpClient(f.Address.AddressFamily); await client.ConnectAsync(endpoint, token).ConfigureAwait(true);
        var stream = client.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        await stream.WriteAsync(TcpSessionFixture.Frame(request), token).ConfigureAwait(true);
        var first = new byte[1];
        try { _ = await stream.ReadAsync(first, token).ConfigureAwait(true); }
        catch (IOException) { }
    }

    [Fact]
    public async Task OneAcceptedIdleConnectionRetainsItsSlotUntilActualEof()
    {
        var f = new NativeClientListenerFixture(connections: 1, messages: 1); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var endpoint = await f.StartAsync(deadline.Token).ConfigureAwait(true);
        using var first = new TcpClient(f.Address.AddressFamily); await first.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(true);
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Listener.ActiveTcpConnections == 1).ConfigureAwait(true);
        using var second = new TcpClient(f.Address.AddressFamily); await second.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(true);
        var stream = second.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        await stream.WriteAsync(TcpSessionFixture.Frame(ClientRequestFixture.Request()), deadline.Token).ConfigureAwait(true);
        var reply = NativeClientListenerFixture.ReadFrameAsync(stream, deadline.Token);
        Assert.False(reply.IsCompleted); Assert.Empty(f.Epoch.Calls); Assert.Equal(1, f.Listener.ActiveTcpConnections);
        first.Dispose();
        Assert.True((await reply.ConfigureAwait(true)).Length >= 12);
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Listener.ActiveTcpConnections == 0).ConfigureAwait(true);
        Assert.Equal(2, f.Epoch.Calls.Count);
    }
}
