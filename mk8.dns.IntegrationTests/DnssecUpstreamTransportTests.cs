using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class DnssecUpstreamTransportTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RealUdpRequestsDoCdAndPreservesCompleteUntrustedEvidence(bool ipv6)
    {
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10)); using var server = DnssecUpstreamFixture.Bind(ipv6);
        var peer = DnssecUpstreamFixture.Endpoint(server);
        var worker = Task.Run(async () =>
        {
            var received = await server.ReceiveAsync(closure.Token).ConfigureAwait(true);
            var request = DnsMessageCodec.DecodeQuery(received.Buffer);
            Assert.Equal((ushort)0x0010, request.Flags); Assert.True(request.DnssecOk); Assert.Equal((ushort)1232, request.UdpPayloadSize);
            await server.SendAsync(DnssecUpstreamFixture.Reply(received.Buffer, 0x84b1, extendedCode: 0xff), received.RemoteEndPoint, closure.Token).ConfigureAwait(true);
        }, closure.Token);
        try
        {
            var client = new DnssecUpstreamClient(endpoint => endpoint.Equals(peer), TimeSpan.FromSeconds(3));
            var result = await client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, peer, closure.Token).ConfigureAwait(true);
            Assert.Equal((ushort)4081, result.ResponseCode); Assert.True(result.AuthenticatedDataObserved); Assert.True(result.CheckingDisabledObserved);
            Assert.True(result.DnssecOkObserved); Assert.Equal(peer, result.Server); Assert.Equal((byte)42, Assert.Single(result.Answers).GetData()[3]);
        }
        finally
        {
            await closure.CancelAsync().ConfigureAwait(true);
            try { await worker.ConfigureAwait(true); }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidSourceIdentityQuestionAndOversizedDatagramsAreDiscarded(bool ipv6)
    {
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10)); using var server = DnssecUpstreamFixture.Bind(ipv6); using var stranger = DnssecUpstreamFixture.Bind(ipv6);
        var worker = Task.Run(async () =>
        {
            var request = await server.ReceiveAsync(closure.Token).ConfigureAwait(true); var good = DnssecUpstreamFixture.Reply(request.Buffer);
            var forged = good.ToArray(); forged[^12] ^= 1;
            await stranger.SendAsync(forged, request.RemoteEndPoint, closure.Token).ConfigureAwait(true);
            var wrongId = good.ToArray(); wrongId[0] ^= 1; await server.SendAsync(wrongId, request.RemoteEndPoint, closure.Token).ConfigureAwait(true);
            var wrongQuestion = good.ToArray(); wrongQuestion[13] = (byte)'z'; await server.SendAsync(wrongQuestion, request.RemoteEndPoint, closure.Token).ConfigureAwait(true);
            var oversized = DnssecUpstreamFixture.Reply(request.Buffer, data: new byte[1500]); await server.SendAsync(oversized, request.RemoteEndPoint, closure.Token).ConfigureAwait(true);
            await server.SendAsync(good, request.RemoteEndPoint, closure.Token).ConfigureAwait(true);
        }, closure.Token);
        try
        {
            var result = await new DnssecUpstreamClient(_ => true, TimeSpan.FromSeconds(3)).ExchangeDnssecAsync(DnssecUpstreamFixture.Question, DnssecUpstreamFixture.Endpoint(server), closure.Token).ConfigureAwait(true);
            Assert.Equal((byte)42, Assert.Single(result.Answers).GetData()[3]); Assert.Equal((ushort)0, result.ResponseCode);
        }
        finally
        {
            await closure.CancelAsync().ConfigureAwait(true);
            try { await worker.ConfigureAwait(true); }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task TcpRetryReusesExactDoCdTransactionAndRefusesPersistentTc(bool ipv6, bool persistentTc)
    {
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10)); using var udp = DnssecUpstreamFixture.Bind(ipv6);
        var server = DnssecUpstreamFixture.Endpoint(udp); using var tcp = new TcpListener(new IPEndPoint(new IPAddress(server.GetAddress()), server.Port)); tcp.Start();
        byte[]? datagram = null;
        var udpWorker = Task.Run(async () =>
        {
            var received = await udp.ReceiveAsync(closure.Token).ConfigureAwait(true); datagram = received.Buffer;
            var response = DnssecUpstreamFixture.Reply(received.Buffer, 0x8630); await udp.SendAsync(response.AsMemory(0, response.Length - 5), received.RemoteEndPoint, closure.Token).ConfigureAwait(true);
        }, closure.Token);
        var tcpWorker = Task.Run(async () =>
        {
            using var peer = await tcp.AcceptTcpClientAsync(closure.Token).ConfigureAwait(true); using var stream = peer.GetStream();
            var frame = await DnssecUpstreamFixture.ReadFrameAsync(stream, closure.Token).ConfigureAwait(true); Assert.Equal(datagram, frame);
            Assert.True(DnsMessageCodec.DecodeQuery(frame).DnssecOk);
            await DnssecUpstreamFixture.SendFrameAsync(stream, DnssecUpstreamFixture.Reply(frame, persistentTc ? (ushort)0x8630 : (ushort)0x8430, [192, 0, 2, 43]), closure.Token).ConfigureAwait(true);
        }, closure.Token);
        try
        {
            var client = new DnssecUpstreamClient(_ => true, TimeSpan.FromSeconds(3));
            if (persistentTc) _ = await Assert.ThrowsAsync<IOException>(() => client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, server, closure.Token).AsTask()).ConfigureAwait(true);
            else Assert.Equal((byte)43, Assert.Single((await client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, server, closure.Token).ConfigureAwait(true)).Answers).GetData()[3]);
        }
        finally
        {
            await closure.CancelAsync().ConfigureAwait(true);
            try { await Task.WhenAll(udpWorker, tcpWorker).ConfigureAwait(true); }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
    }

    [Fact]
    public async Task RevocationBeforeTcpDoesNotOpenTheListener()
    {
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10)); using var udp = DnssecUpstreamFixture.Bind(false);
        var server = DnssecUpstreamFixture.Endpoint(udp); using var tcp = new TcpListener(new IPEndPoint(IPAddress.Loopback, server.Port)); tcp.Start(); var policyCalls = 0;
        var worker = Task.Run(async () =>
        {
            var received = await udp.ReceiveAsync(closure.Token).ConfigureAwait(true);
            await udp.SendAsync(DnssecUpstreamFixture.Reply(received.Buffer, 0x8630), received.RemoteEndPoint, closure.Token).ConfigureAwait(true);
        }, closure.Token);
        try
        {
            var client = new DnssecUpstreamClient(_ => Interlocked.Increment(ref policyCalls) == 1, TimeSpan.FromSeconds(3));
            _ = await Assert.ThrowsAsync<IOException>(() => client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, server, closure.Token).AsTask()).ConfigureAwait(true);
            Assert.Equal(2, policyCalls); Assert.False(tcp.Pending());
        }
        finally
        {
            await closure.CancelAsync().ConfigureAwait(true);
            try { await worker.ConfigureAwait(true); }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
    }

    [Fact]
    public async Task CallerCancellationDeadlineAndPreEgressRefusalAreDistinct()
    {
        using var server = DnssecUpstreamFixture.Bind(false); var endpoint = DnssecUpstreamFixture.Endpoint(server);
        _ = await Assert.ThrowsAsync<IOException>(() => new DnssecUpstreamClient(_ => false, TimeSpan.FromSeconds(1)).ExchangeDnssecAsync(DnssecUpstreamFixture.Question, endpoint, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, server.Available);
        var client = new DnssecUpstreamClient(_ => true, TimeSpan.FromMilliseconds(100));
        _ = await Assert.ThrowsAsync<TimeoutException>(() => client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, endpoint, CancellationToken.None).AsTask()).ConfigureAwait(true);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ExchangeDnssecAsync(DnssecUpstreamFixture.Question, endpoint, cancellation.Token).AsTask()).ConfigureAwait(true);
    }
}
