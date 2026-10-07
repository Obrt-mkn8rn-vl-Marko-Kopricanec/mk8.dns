using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecUpstreamDeadlineTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UdpTimeIsChargedToTheSameTcpDeadlineAndTimerDrains(bool ipv6)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var clock = new RecursiveCacheClock();
        using var udp = Bind(ipv6);
        var endpoint = (IPEndPoint)udp.Client.LocalEndPoint!;
        using var tcp = new TcpListener(endpoint); tcp.Start();
        var accepted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var udpWorker = Task.Run(async () =>
        {
            var received = await udp.ReceiveAsync(guard.Token).ConfigureAwait(true);
            clock.Set(TimeSpan.FromMilliseconds(200));
            var truncated = received.Buffer.AsSpan(0, QuestionEnd(received.Buffer)).ToArray();
            BinaryPrimitives.WriteUInt16BigEndian(truncated.AsSpan(2), 0x8630); BinaryPrimitives.WriteUInt16BigEndian(truncated.AsSpan(10), 0);
            await udp.SendAsync(truncated, received.RemoteEndPoint, guard.Token).ConfigureAwait(true);
        }, guard.Token);
        var tcpWorker = Task.Run(async () =>
        {
            using var peer = await tcp.AcceptTcpClientAsync(guard.Token).ConfigureAwait(true); using var stream = peer.GetStream();
            var prefix = new byte[2]; await stream.ReadExactlyAsync(prefix, guard.Token).ConfigureAwait(true);
            var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)]; await stream.ReadExactlyAsync(query, guard.Token).ConfigureAwait(true);
            accepted.SetResult();
            _ = await stream.ReadAsync(prefix, guard.Token).ConfigureAwait(true);
        }, guard.Token);
        try
        {
            var client = new DnssecUpstreamClient(_ => true, TimeSpan.FromSeconds(1), clock);
            var result = client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, new DnsServerEndpoint(endpoint.Address.GetAddressBytes(), (ushort)endpoint.Port), guard.Token).AsTask();
            await accepted.Task.WaitAsync(guard.Token).ConfigureAwait(true);
            Assert.Equal(1, clock.ActiveTimers); clock.Set(TimeSpan.FromMilliseconds(999)); Assert.False(result.IsCompleted);
            clock.Set(TimeSpan.FromSeconds(1));
            Exception? error = null;
            try { await result.WaitAsync(guard.Token).ConfigureAwait(true); }
            catch (TimeoutException caught) { error = caught; }
            Assert.IsType<TimeoutException>(error);
            Assert.Equal(0, clock.ActiveTimers);
        }
        finally
        {
            await guard.CancelAsync().ConfigureAwait(true);
            try { await Task.WhenAll(udpWorker, tcpWorker).ConfigureAwait(true); }
            catch (OperationCanceledException) when (guard.IsCancellationRequested) { }
        }
    }

    [Fact]
    public async Task CancellationWhileUdpPendingReleasesTheOwnedTimer()
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10)); using var caller = new CancellationTokenSource();
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var endpoint = (IPEndPoint)server.Client.LocalEndPoint!;
        var clock = new RecursiveCacheClock(); var client = new DnssecUpstreamClient(_ => true, TimeSpan.FromSeconds(1), clock);
        var task = client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, new DnsServerEndpoint(endpoint.Address.GetAddressBytes(), (ushort)endpoint.Port), caller.Token).AsTask();
        _ = await server.ReceiveAsync(guard.Token).ConfigureAwait(true); Assert.Equal(1, clock.ActiveTimers);
        await caller.CancelAsync().ConfigureAwait(true);
        Exception? error = null;
        try { await task.WaitAsync(guard.Token).ConfigureAwait(true); }
        catch (OperationCanceledException caught) when (!guard.IsCancellationRequested && caller.IsCancellationRequested) { error = caught; }
        Assert.IsAssignableFrom<OperationCanceledException>(error); Assert.Equal(0, clock.ActiveTimers);
    }

    private static UdpClient Bind(bool ipv6)
    {
        var udp = new UdpClient(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        if (ipv6) udp.Client.DualMode = false;
        udp.Client.Bind(new IPEndPoint(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0));
        return udp;
    }

    private static int QuestionEnd(byte[] bytes)
    {
        var end = 12; while (bytes[end] != 0) end += bytes[end] + 1; return end + 5;
    }
}
