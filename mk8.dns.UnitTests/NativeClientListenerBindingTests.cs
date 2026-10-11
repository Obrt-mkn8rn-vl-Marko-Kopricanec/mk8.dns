using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeClientListenerBindingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedSecondProtocolBindClosesFirstOwnedSocketWithoutFallback(bool ipv6)
    {
        var address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        using var occupied = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (ipv6) occupied.DualMode = false;
        occupied.Bind(new IPEndPoint(address, 0));
        var endpoint = Assert.IsType<IPEndPoint>(occupied.LocalEndPoint);
        var f = new NativeClientListenerFixture(ipv6, binding: endpoint); await using var lifetime = f.ConfigureAwait(true);
        var running = f.Listener.RunAsync(CancellationToken.None);
        var error = await Assert.ThrowsAsync<SocketException>(() => running.WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        f.ExpectedFailure = error;
        Assert.Equal(SocketError.AddressAlreadyInUse, error.SocketErrorCode);
        var boundError = await Assert.ThrowsAsync<SocketException>(() => f.Listener.WaitForBoundAsync(CancellationToken.None)).ConfigureAwait(true);
        Assert.Same(error, boundError);
        var closeError = await Assert.ThrowsAsync<SocketException>(() => f.Listener.DisposeAsync().AsTask()).ConfigureAwait(true);
        Assert.Same(error, closeError);
        using var successor = new TcpListener(endpoint); if (ipv6) successor.Server.DualMode = false;
        successor.Start(); Assert.Equal(endpoint, successor.LocalEndpoint);
        Assert.Empty(f.Epoch.Calls); Assert.Equal(0, f.Listener.ActiveTcpConnections);
    }

    [Fact]
    public async Task MutatingCallerEndpointDoesNotChangeSnapshottedBind()
    {
        var f = new NativeClientListenerFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var caller = new IPEndPoint(IPAddress.Loopback, 0);
        var listener = new DnssecClientListener(f.Processor, caller);
        await using var listenerLifetime = listener.ConfigureAwait(true);
        caller.Address = IPAddress.Any; caller.Port = 1;
        var running = listener.RunAsync(deadline.Token);
        var actual = await listener.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(IPAddress.Loopback, actual.Address); Assert.NotEqual(0, actual.Port);
        var reply = await NativeClientListenerFixture.UdpAsync(actual, ClientRequestFixture.Request(), deadline.Token).ConfigureAwait(true);
        Assert.True(reply.Length >= 12);
        await listener.DisposeAsync().ConfigureAwait(true); await running.ConfigureAwait(true);
        Assert.Equal(0, f.Processor.ActiveRequests);
    }
}
