using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Contracts;
using Mk8.Dns.Presentation;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ListenerLifetimeTests
{
    [Fact]
    public async Task CancellationDrainsPartialFramesAndReleasesBothBindings()
    {
        using var reservation = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        reservation.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = (IPEndPoint)reservation.LocalEndPoint!;
        reservation.Dispose();
        using var stop = new CancellationTokenSource();
        var listener = new AuthoritativeListener(endpoint, new Echo());
        var run = listener.RunAsync(stop.Token);
        List<TcpClient> clients = [];
        try
        {
            for (var index = 0; index < 16; index++)
            {
                var client = new TcpClient(AddressFamily.InterNetwork);
                clients.Add(client);
                await client.ConnectAsync(endpoint, CancellationToken.None).ConfigureAwait(true);
                await client.GetStream().WriteAsync(new byte[] { 0 }, CancellationToken.None).ConfigureAwait(true);
            }
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(true);
            try
            {
                await run.ConfigureAwait(true);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            foreach (var client in clients)
                client.Dispose();
        }
        Assert.True(run.IsCompleted);
        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udp.Bind(endpoint);
        using var tcp = new TcpListener(endpoint);
        tcp.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        tcp.Start();
    }

    private sealed class Echo : IDnsExchange
    {
        public ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken) => ValueTask.FromResult(message.ToArray());
    }
}
