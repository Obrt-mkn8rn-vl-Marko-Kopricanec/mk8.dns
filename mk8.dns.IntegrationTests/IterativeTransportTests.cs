using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class IterativeTransportTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OwnedRootAndChildResolveWithoutForwarding(bool ipv6)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var root = new OwnedUdpReply(ipv6, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OwnedUdpReply(ipv6, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        var childAddress = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        var port = child.Server.Port;
        root.Start(query =>
        {
            Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2)));
            return Reply(query, 0x8000, [], [Record("example.", 2, DnsName.Parse("ns.example.").ToWire())], [Record("ns.example.", ipv6 ? (ushort)28 : (ushort)1, childAddress.GetAddressBytes())]);
        });
        child.Start(query => Reply(query, 0x8400, [Record("www.example.", 1, [192, 0, 2, 42])], [], []));
        var client = new DnsUpstreamClient(endpoint => new IPAddress(endpoint.GetAddress()).Equals(childAddress), TimeSpan.FromSeconds(2));
        var resolver = new NonValidatingIterativeResolver(client, [root.Server], port);
        var answer = await resolver.ResolveAsync(Q(), deadline.Token).ConfigureAwait(true);
        Assert.Equal(0, answer.ResponseCode);
        Assert.False(answer.Authoritative);
        Assert.Equal(new byte[] { 192, 0, 2, 42 }, Assert.Single(answer.Answers).GetData());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WrongIdQuestionAndSourcePortAreDiscarded(bool ipv6)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var server = Bind(ipv6);
        using var stranger = Bind(ipv6);
        var work = Task.Run(async () =>
        {
            var received = await server.ReceiveAsync(deadline.Token).ConfigureAwait(true);
            var good = Reply(received.Buffer, 0x8400, [Record("www.example.", 1, [192, 0, 2, 42])], [], []);
            var forged = (byte[])good.Clone(); forged[^1] = 99;
            await stranger.SendAsync(forged, received.RemoteEndPoint, deadline.Token).ConfigureAwait(true);
            var badId = (byte[])forged.Clone(); badId[0] ^= 1;
            await server.SendAsync(badId, received.RemoteEndPoint, deadline.Token).ConfigureAwait(true);
            var badQuestion = (byte[])forged.Clone(); badQuestion[13] = (byte)'z';
            await server.SendAsync(badQuestion, received.RemoteEndPoint, deadline.Token).ConfigureAwait(true);
            await server.SendAsync(good, received.RemoteEndPoint, deadline.Token).ConfigureAwait(true);
        }, deadline.Token);
        try
        {
            var result = await new DnsUpstreamClient(_ => true, TimeSpan.FromSeconds(2)).ExchangeAsync(Q(), Endpoint(server), deadline.Token).ConfigureAwait(true);
            Assert.Equal((byte)42, Assert.Single(result.Answers).GetData()[3]);
        }
        finally
        {
            await deadline.CancelAsync().ConfigureAwait(true);
            try { await work.ConfigureAwait(true); }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task TruncationRetriesExactTransactionOverFramedTcp(bool ipv6, bool truncatedTcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var udp = new OwnedUdpReply(ipv6, deadline.Token);
        await using var udpLifetime = udp.ConfigureAwait(true);
        var local = new IPEndPoint(new IPAddress(udp.Server.GetAddress()), udp.Server.Port);
        using var tcp = new TcpListener(local); tcp.Start();
        byte[]? datagram = null;
        udp.Start(query => { datagram = query; return Reply(query, 0x8600, [], [], []); });
        var tcpWork = Task.Run(async () =>
        {
            using var peer = await tcp.AcceptTcpClientAsync(deadline.Token).ConfigureAwait(true);
            using var stream = peer.GetStream();
            var prefix = new byte[2];
            await stream.ReadExactlyAsync(prefix, deadline.Token).ConfigureAwait(true);
            var message = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
            await stream.ReadExactlyAsync(message, deadline.Token).ConfigureAwait(true);
            Assert.Equal(datagram, message);
            var response = Reply(message, truncatedTcp ? (ushort)0x8600 : (ushort)0x8400, [Record("www.example.", 1, [192, 0, 2, 43])], [], []);
            BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)response.Length);
            await stream.WriteAsync(prefix.AsMemory(0, 1), deadline.Token).ConfigureAwait(true);
            await stream.WriteAsync(prefix.AsMemory(1), deadline.Token).ConfigureAwait(true);
            await stream.WriteAsync(response.AsMemory(0, 13), deadline.Token).ConfigureAwait(true);
            await stream.WriteAsync(response.AsMemory(13), deadline.Token).ConfigureAwait(true);
        }, deadline.Token);
        try
        {
            var client = new DnsUpstreamClient(_ => true, TimeSpan.FromSeconds(3));
            if (truncatedTcp)
                _ = await Assert.ThrowsAsync<IOException>(() => client.ExchangeAsync(Q(), udp.Server, deadline.Token).AsTask()).ConfigureAwait(true);
            else
                Assert.Equal((byte)43, Assert.Single((await client.ExchangeAsync(Q(), udp.Server, deadline.Token).ConfigureAwait(true)).Answers).GetData()[3]);
        }
        finally
        {
            await deadline.CancelAsync().ConfigureAwait(true);
            try { await tcpWork.ConfigureAwait(true); }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        }
    }

    [Fact]
    public async Task TimeoutCancellationAndEgressRefusalAreDistinct()
    {
        using var server = Bind(false);
        var endpoint = Endpoint(server);
        _ = await Assert.ThrowsAsync<IOException>(() => new DnsUpstreamClient(_ => false, TimeSpan.FromSeconds(1)).ExchangeAsync(Q(), endpoint, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, server.Available);
        var client = new DnsUpstreamClient(_ => true, TimeSpan.FromMilliseconds(100));
        _ = await Assert.ThrowsAsync<TimeoutException>(() => client.ExchangeAsync(Q(), endpoint, CancellationToken.None).AsTask()).ConfigureAwait(true);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ExchangeAsync(Q(), endpoint, cancellation.Token).AsTask()).ConfigureAwait(true);
    }

    private static DnsQuestion Q() => new(DnsName.Parse("www.example."), 1, 1);
    private static DnsServerEndpoint Endpoint(UdpClient client)
    {
        var address = (IPEndPoint)client.Client.LocalEndPoint!;
        return new DnsServerEndpoint(address.Address.GetAddressBytes(), (ushort)address.Port);
    }
    private static UdpClient Bind(bool ipv6)
    {
        var result = new UdpClient(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        if (ipv6) result.Client.DualMode = false;
        result.Client.Bind(new IPEndPoint(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0));
        return result;
    }
    private static async Task ReplyOnceAsync(UdpClient client, Func<byte[], byte[]> response, CancellationToken cancellationToken)
    {
        try
        {
            var request = await client.ReceiveAsync(cancellationToken).ConfigureAwait(true);
            await client.SendAsync(response(request.Buffer), request.RemoteEndPoint, cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Test-owned listeners are joined before their sockets are disposed, including failure paths.
        }
    }
    private sealed class OwnedUdpReply : IAsyncDisposable
    {
        private readonly UdpClient client;
        private readonly CancellationTokenSource closure;
        private readonly List<Task> workers = [];
        public OwnedUdpReply(bool ipv6, CancellationToken cancellationToken)
        {
            client = Bind(ipv6);
            closure = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Server = Endpoint(client);
        }
        public DnsServerEndpoint Server { get; }
        public void Start(Func<byte[], byte[]> response)
        {
            if (workers.Count != 0)
                throw new InvalidOperationException("An owned fixture accepts one reply worker.");
            workers.Add(ReplyOnceAsync(client, response, closure.Token));
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                await closure.CancelAsync().ConfigureAwait(true);
                await Task.WhenAll(workers).ConfigureAwait(true);
            }
            finally
            {
                client.Dispose();
                closure.Dispose();
            }
        }
    }
    private static byte[] Record(string owner, ushort type, byte[] data)
    {
        var name = DnsName.Parse(owner).ToWire();
        var result = new byte[name.Length + 10 + data.Length]; name.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(name.Length), type);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(name.Length + 2), 1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(name.Length + 4), 300);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(name.Length + 8), (ushort)data.Length);
        data.CopyTo(result, name.Length + 10); return result;
    }
    private static byte[] Reply(byte[] query, ushort flags, byte[][] answers, byte[][] authority, byte[][] additional)
    {
        var end = 12;
        while (query[end] != 0) end += query[end] + 1;
        end += 5;
        var result = new byte[end + answers.Concat(authority).Concat(additional).Sum(record => record.Length)];
        query.AsSpan(0, end).CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), (ushort)answers.Length);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), (ushort)authority.Length);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), (ushort)additional.Length);
        foreach (var record in answers.Concat(authority).Concat(additional)) { record.CopyTo(result, end); end += record.Length; }
        return result;
    }
}
