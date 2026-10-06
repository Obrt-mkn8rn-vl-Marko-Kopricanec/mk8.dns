using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Mk8.Dns.Contracts;
using Mk8.Dns.Presentation;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ListenerLifetimeTests
{
    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("::%1")]
    [InlineData("::ffff:0.0.0.0")]
    public void DirectListenerConstructionRejectsWildcardAddresses(string address) => Assert.Throws<ArgumentException>(() => new AuthoritativeListener(new IPEndPoint(IPAddress.Parse(address), 5353), new Echo()));

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.2")]
    public Task UdpReplyPreservesSpecificIpv4Destination(string address) => AssertUdpSourceAsync(IPAddress.Parse(address));

    public static TheoryData<string> AssignedIpv6Addresses()
    {
        var data = new TheoryData<string>();
        foreach (var address in NetworkInterface.GetAllNetworkInterfaces().Where(adapter => adapter.OperationalStatus == OperationalStatus.Up)
            .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses).Select(item => item.Address)
            .Where(address => address.AddressFamily == AddressFamily.InterNetworkV6 && !address.IsIPv6LinkLocal)
            .Distinct().OrderBy(address => address.ToString(), StringComparer.Ordinal))
            data.Add(address.ToString());
        return data;
    }

    [Theory]
    [MemberData(nameof(AssignedIpv6Addresses))]
    public Task UdpReplyPreservesAssignedIpv6Destination(string address) => AssertUdpSourceAsync(IPAddress.Parse(address));

    private static async Task AssertUdpSourceAsync(IPAddress address)
    {
        using var reservation = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        reservation.Bind(new IPEndPoint(address, 0));
        var endpoint = (IPEndPoint)reservation.LocalEndPoint!;
        reservation.Dispose();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var listener = new AuthoritativeListener(endpoint, new Echo());
        var run = listener.RunAsync(stop.Token);
        try
        {
            using var udp = new UdpClient(address.AddressFamily);
            byte[] message = [0xab, 0xcd, 1, 0];
            _ = await udp.SendAsync(message, endpoint, stop.Token).ConfigureAwait(true);
            var reply = await udp.ReceiveAsync(stop.Token).ConfigureAwait(true);
            Assert.Equal(endpoint, reply.RemoteEndPoint);
            Assert.Equal(message, reply.Buffer);
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(true);
            try
            {
                await run.ConfigureAwait(true);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
    }

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
