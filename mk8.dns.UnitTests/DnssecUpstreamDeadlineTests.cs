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
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task UdpTimeIsChargedToTheSameTcpDeadlineAndTimerDrains(bool ipv6, bool observerFailure)
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
            using var peer = await tcp.AcceptTcpClientAsync(guard.Token).ConfigureAwait(true); var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
            var prefix = new byte[2]; await stream.ReadExactlyAsync(prefix, guard.Token).ConfigureAwait(true);
            var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)]; await stream.ReadExactlyAsync(query, guard.Token).ConfigureAwait(true);
            accepted.SetResult();
            _ = await stream.ReadAsync(prefix, guard.Token).ConfigureAwait(true);
        }, guard.Token);
        await CheckExchangeAsync(clock, endpoint, accepted.Task, Task.WhenAll(udpWorker, tcpWorker), guard, observerFailure).ConfigureAwait(true);
    }

    private static async Task CheckExchangeAsync(RecursiveCacheClock clock, IPEndPoint endpoint, Task accepted, Task servers, CancellationTokenSource guard, bool observerFailure)
    {
        var client = new DnssecUpstreamClient(_ => true, TimeSpan.FromSeconds(1), clock);
        var result = client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, new DnsServerEndpoint(endpoint.Address.GetAddressBytes(), (ushort)endpoint.Port), guard.Token).AsTask();
        var observer = new IOException("Controlled TCP entry observer failure.");
        var observed = await Record.ExceptionAsync(() => TestTaskSettlement.RunAsync(async () =>
        {
            await accepted.WaitAsync(guard.Token).ConfigureAwait(true);
            if (observerFailure) throw observer;
            Assert.Equal(1, clock.ActiveTimers); clock.Set(TimeSpan.FromMilliseconds(999)); Assert.False(result.IsCompleted);
            clock.Set(TimeSpan.FromSeconds(1));
            await Assert.ThrowsAsync<TimeoutException>(() => result.WaitAsync(guard.Token)).ConfigureAwait(true);
            Assert.Equal(0, clock.ActiveTimers);
        }, async () => await TestTaskSettlement.RunAsync(() => guard.CancelAsync(), async () =>
        {
            await TestTaskSettlement.RunAsync(async () =>
            {
                var error = await Record.ExceptionAsync(() => result.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
                Assert.True(error is OperationCanceledException or TimeoutException);
            }, async () =>
            {
                try { await servers.WaitAsync(CancellationToken.None).ConfigureAwait(true); }
                catch (OperationCanceledException) when (guard.IsCancellationRequested) { }
            }).ConfigureAwait(true);
        }).ConfigureAwait(true))).ConfigureAwait(true);
        if (observerFailure) Assert.Same(observer, observed);
        else Assert.Null(observed);
        Assert.True(result.IsCompleted);
        Assert.Equal(0, clock.ActiveTimers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationWhileUdpPendingReleasesTheOwnedTimer(bool observerFailure)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var caller = new CancellationTokenSource();
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = (IPEndPoint)server.Client.LocalEndPoint!;
        var clock = new RecursiveCacheClock();
        var client = new DnssecUpstreamClient(_ => true, TimeSpan.FromSeconds(1), clock);
        var task = client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question,
            new DnsServerEndpoint(endpoint.Address.GetAddressBytes(), (ushort)endpoint.Port), caller.Token).AsTask();
        var observer = new IOException("Controlled UDP entry observer failure.");
        var observed = await Record.ExceptionAsync(() => TestTaskSettlement.RunAsync(async () =>
        {
            _ = await server.ReceiveAsync(guard.Token).ConfigureAwait(true);
            Assert.Equal(1, clock.ActiveTimers);
            if (observerFailure) throw observer;
        }, async () => await TestTaskSettlement.RunAsync(() => caller.CancelAsync(), async () =>
        {
            await TestTaskSettlement.RunAsync(async () =>
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task.WaitAsync(guard.Token)).ConfigureAwait(true), async () =>
            {
                var error = await Record.ExceptionAsync(() => task.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
                if (error is not OperationCanceledException) Assert.Null(error);
            }).ConfigureAwait(true);
        }).ConfigureAwait(true))).ConfigureAwait(true);
        if (observerFailure) Assert.Same(observer, observed);
        else Assert.Null(observed);
        Assert.True(task.IsCanceled);
        Assert.Equal(0, clock.ActiveTimers);
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
