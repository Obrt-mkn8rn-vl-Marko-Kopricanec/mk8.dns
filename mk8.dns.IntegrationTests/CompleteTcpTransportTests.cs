using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class CompleteTcpTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CompleteTcpProfilePreservesOwnedNativeAliasDenialAndUdpResponses(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var clock = new MessageClock();
        var tracker = new DnssecTrustAnchorTracker(zones.Anchor.Origin, [zones.Anchor.Record], OnlineDnssecWireFixture.Verifier, clock);
        var store = new TrustEpochLifetimeWireFixture.PinnedStore(new DnssecStoredAnchorCheckpoint(tracker.Origin, 1, tracker.CreateCheckpoint()));
        var refresher = new DnssecAnchorRefresher(tracker.Origin, store, upstream, OnlineDnssecWireFixture.Verifier, root.Server, clock);
        await using var refreshLifetime = refresher.ConfigureAwait(true);
        var source = DnssecTrustEpochResolver.CreateWithClientProof(refresher, upstream, OnlineDnssecWireFixture.Verifier,
            [root.Server], new DnssecTrustEpochPolicy(), child.Server.Port);
        await using var sourceLifetime = source.ConfigureAwait(true);
        var peer = root.Server.GetAddress();
        var processor = DnssecClientRequestProcessor.CreateWithCompleteTcpAnswers(source, new DnssecClientAccessPolicy([new DnssecClientNetwork(peer, peer.Length * 8)], authenticatedDataAllowed: true));
        await using var processorLifetime = processor.ConfigureAwait(true);
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var listener = Tcp;
        try { await ExerciseAsync(root, child, processor, clock, udp, listener, tcp, deadline.Token).ConfigureAwait(true); }
        finally { await deadline.CancelAsync().ConfigureAwait(true); }
        Assert.Equal(0, processor.ActiveRequests); Assert.Equal(0, source.Statistics.ActiveRequests);
    }

    private static async Task ExerciseAsync(OnlineDnssecWireFixture.Node root, OnlineDnssecWireFixture.Node child,
        DnssecClientRequestProcessor processor, MessageClock clock, UdpClient udp, TcpListener listener, bool tcp, CancellationToken token)
    {
        foreach (var name in new[] { "alias.example.", "missing.child.example." })
        {
            var question = new DnsQuestion(DnsName.Parse(name), 1, 1); var before = -1;
            foreach (var dnssecOk in new[] { false, true })
            {
                var request = UpstreamMessageCodec.EncodeDnssecQuery(19, question);
                BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0100);
                if (!dnssecOk) request[^4] = 0;
                var answering = AnswerAsync(processor, udp, listener, tcp, token);
                var querying = QueryAsync(DnssecUpstreamFixture.Endpoint(udp), request, tcp, token);
                await Task.WhenAll(answering, querying).ConfigureAwait(true);
                var bytes = await querying.ConfigureAwait(true);
                var decoded = UpstreamMessageCodec.DecodeDnssecResponse(bytes, 19, question, root.Server);
                Assert.False(decoded.Truncated); Assert.Equal(dnssecOk, (decoded.Evidence.Flags & 32) != 0);
                Assert.Equal(name.StartsWith("missing", StringComparison.Ordinal) ? 3 : 0, decoded.Evidence.ResponseCode);
                Assert.DoesNotContain(decoded.Evidence.Answers.Concat(decoded.Evidence.Authority), record => record.Type is 2 or 43 or 48);
                Assert.Empty(decoded.Evidence.Additional);
                var calls = root.Requests.Count + child.Requests.Count;
                if (before >= 0) Assert.Equal(before, calls);
                before = calls; clock.Advance(1);
            }
        }
    }

    private static async Task AnswerAsync(DnssecClientRequestProcessor processor, UdpClient udp, TcpListener listener,
        bool tcp, CancellationToken token)
    {
        if (!tcp)
        {
            var request = await udp.ReceiveAsync(token).ConfigureAwait(true);
            var result = await processor.ProcessAsync(request.Buffer, request.RemoteEndPoint.Address.GetAddressBytes(), tcp: false, token).ConfigureAwait(true);
            Assert.Equal(DnssecClientReplyOutcome.Encoded, result.Outcome);
            await udp.SendAsync(result.GetMessage(), request.RemoteEndPoint, token).ConfigureAwait(true);
            return;
        }
        using var peer = await listener.AcceptTcpClientAsync(token).ConfigureAwait(true);
        var endpoint = Assert.IsType<IPEndPoint>(peer.Client.RemoteEndPoint);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(false);
        var packet = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
        var reply = await processor.ProcessAsync(packet, endpoint.Address.GetAddressBytes(), tcp: true, token).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, reply.Outcome);
        await DnssecUpstreamFixture.SendFrameAsync(stream, reply.GetMessage(), token).ConfigureAwait(true);
    }

    private static async Task<byte[]> QueryAsync(DnsServerEndpoint endpoint, byte[] packet, bool tcp, CancellationToken token)
    {
        var address = new IPAddress(endpoint.GetAddress());
        if (!tcp)
        {
            using var client = new UdpClient(address.AddressFamily); client.Connect(address, endpoint.Port);
            await client.SendAsync(packet, token).ConfigureAwait(true);
            return (await client.ReceiveAsync(token).ConfigureAwait(true)).Buffer;
        }
        using var peer = new TcpClient(address.AddressFamily);
        await peer.ConnectAsync(address, endpoint.Port, token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(false);
        await DnssecUpstreamFixture.SendFrameAsync(stream, packet, token).ConfigureAwait(true);
        return await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
    }

    private sealed class MessageClock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => ticks;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100).AddTicks(ticks);
        internal void Advance(int seconds) => ticks += TimeSpan.FromSeconds(seconds).Ticks;
    }
}
