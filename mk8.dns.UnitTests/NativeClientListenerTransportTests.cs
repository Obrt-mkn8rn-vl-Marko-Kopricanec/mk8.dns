using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeClientListenerTransportTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualBothProtocolsShareOneBindingAndCachesRemainProofFenced(bool ipv6)
    {
        var f = new NativeClientListenerFixture(ipv6); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var endpoint = await f.StartAsync(deadline.Token).ConfigureAwait(true);
        var originalPort = endpoint.Port; endpoint.Port = 1;
        endpoint = await f.Listener.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(originalPort, endpoint.Port);
        Assert.Throws<InvalidOperationException>((Action)(() => _ = f.Listener.RunAsync(deadline.Token)));
        var request = ClientRequestFixture.Request();
        var udp = await NativeClientListenerFixture.UdpAsync(endpoint, request, deadline.Token).ConfigureAwait(true);
        using var peer = new TcpClient(f.Address.AddressFamily); await peer.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        await stream.WriteAsync(TcpSessionFixture.Frame(request), deadline.Token).ConfigureAwait(true);
        var tcp = await NativeClientListenerFixture.ReadFrameAsync(stream, deadline.Token).ConfigureAwait(true);
        Assert.Equal(udp, tcp); Assert.Equal(32, System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(tcp.AsSpan(2)) & 32);
        Assert.Equal(2, f.Epoch.Calls.Count); Assert.Equal(1, f.Epoch.Resolver.Statistics.Entries);
        var query = DnsMessageCodec.DecodeQuery(request); Assert.NotNull(query.Question);
        Assert.Equal(0, f.Processor.ActiveRequests);
        await f.Listener.DisposeAsync().ConfigureAwait(true);
        await f.Listener.DisposeAsync().ConfigureAwait(true);
        Assert.Equal(0, f.Listener.ActiveTcpConnections);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeniedNativeTcpPeerIsClosedBeforeAnySourceAcquisition(bool ipv6)
    {
        var f = new NativeClientListenerFixture(ipv6, allowed: false); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var endpoint = await f.StartAsync(deadline.Token).ConfigureAwait(true);
        using var peer = new TcpClient(f.Address.AddressFamily); await peer.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(true));
        Assert.Empty(f.Epoch.Calls); Assert.Equal(0, f.Processor.ActiveRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MalformedPeerDoesNotStopOtherConnectionsOrDatagrams(bool partial)
    {
        var f = new NativeClientListenerFixture(connections: 1); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var endpoint = await f.StartAsync(deadline.Token).ConfigureAwait(true);
        using (var peer = new TcpClient(f.Address.AddressFamily))
        {
            await peer.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(true);
            var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
            await stream.WriteAsync(partial ? new byte[1] : [0, 5], deadline.Token).ConfigureAwait(true);
            peer.Client.Shutdown(SocketShutdown.Send);
            Assert.Equal(0, await stream.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(true));
        }
        await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Listener.ActiveTcpConnections == 0).ConfigureAwait(true);
        Assert.NotNull(f.Running); Assert.False(f.Running.IsCompleted);
        var request = ClientRequestFixture.Request();
        var reply = await NativeClientListenerFixture.UdpAsync(endpoint, request, deadline.Token).ConfigureAwait(true);
        Assert.True(reply.Length >= 12); Assert.Equal(2, f.Epoch.Calls.Count);
    }
}
