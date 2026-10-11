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

public sealed class CheckingDisabledTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task OwnedPeerCdPathUsesNativeUnvalidatedAliasAndDenialWithAdClear(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false);
        var root = new CheckingDisabledWireNode(ipv6, forceTcp: tcp, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        var child = new CheckingDisabledWireNode(ipv6, forceTcp: tcp, deadline.Token); await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var permitted = new Func<DnsServerEndpoint, bool>(server => server.Equals(root.Server) || server.Equals(child.Server));
        var checkedUpstream = new DnssecUpstreamClient(permitted, TimeSpan.FromSeconds(3));
        var clock = new FixedClock();
        var tracker = new DnssecTrustAnchorTracker(zones.Anchor.Origin, [zones.Anchor.Record], OnlineDnssecWireFixture.Verifier, clock);
        var store = new TrustEpochLifetimeWireFixture.PinnedStore(new DnssecStoredAnchorCheckpoint(tracker.Origin, 1, tracker.CreateCheckpoint()));
        var refresher = new DnssecAnchorRefresher(tracker.Origin, store, checkedUpstream, OnlineDnssecWireFixture.Verifier, root.Server, clock);
        await using var refreshLifetime = refresher.ConfigureAwait(true);
        var source = DnssecTrustEpochResolver.CreateWithClientProof(refresher, checkedUpstream, OnlineDnssecWireFixture.Verifier,
            [root.Server], new DnssecTrustEpochPolicy(), child.Server.Port); await using var sourceLifetime = source.ConfigureAwait(true);
        var uncheckedSource = new NonValidatingIterativeResolver(new DnsUpstreamClient(permitted, TimeSpan.FromSeconds(3)),
            [root.Server], child.Server.Port, time: clock);
        var address = root.Server.GetAddress();
        var processor = DnssecClientRequestProcessor.CreateWithCheckingDisabledSource(source, uncheckedSource,
            new DnssecClientAccessPolicy([new DnssecClientNetwork(address, address.Length * 8)], authenticatedDataAllowed: true), clock,
            completeTcpAnswers: true); await using var processorLifetime = processor.ConfigureAwait(true);
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var listener = Tcp;
        try { await ExerciseAsync(processor, root, udp, listener, tcp, deadline).ConfigureAwait(true); }
        finally { await deadline.CancelAsync().ConfigureAwait(true); }
        Assert.Equal(0, source.Statistics.Entries); Assert.Equal(0, source.Statistics.FailureEntries); Assert.Equal(0, processor.ActiveRequests);
    }

    private static async Task ExerciseAsync(DnssecClientRequestProcessor processor, CheckingDisabledWireNode root,
        UdpClient udp, TcpListener listener, bool tcp, CancellationTokenSource deadline)
    {
        foreach (var name in new[] { "alias.example.", "missing.child.example." })
        {
            var question = new DnsQuestion(DnsName.Parse(name), 1, 1);
            var request = UpstreamMessageCodec.EncodeQuery(93, question);
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0130);
            var answering = AnswerAsync(processor, udp, listener, tcp, deadline.Token);
            var querying = QueryAsync(DnssecUpstreamFixture.Endpoint(udp), request, tcp, deadline.Token);
            try
            {
                await Task.WhenAll(answering, querying).ConfigureAwait(true);
                var packet = await querying.ConfigureAwait(true);
                Assert.Equal((ushort)(name.StartsWith("missing", StringComparison.Ordinal) ? 0x8193 : 0x8190), BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2)));
                var parsed = UpstreamMessageCodec.DecodeResponse(packet, 93, question).Answer;
                Assert.Equal(name.StartsWith("missing", StringComparison.Ordinal) ? 3 : 0, parsed.ResponseCode);
                Assert.DoesNotContain(parsed.Answers.Concat(parsed.Authority), record => record.Type is 2 or 43 or 46 or 48);
                Assert.Empty(parsed.Additional);
            }
            finally
            {
                if (!answering.IsCompleted || !querying.IsCompleted) await deadline.CancelAsync().ConfigureAwait(true);
                await Task.WhenAll(answering, querying).ConfigureAwait(true);
            }
        }
        var checkedQuery = UpstreamMessageCodec.EncodeQuery(94, new DnsQuestion(DnsName.Parse("alias.example."), 1, 1));
        BinaryPrimitives.WriteUInt16BigEndian(checkedQuery.AsSpan(2), 0x0100);
        var refused = await processor.ProcessAsync(checkedQuery, root.Server.GetAddress(), tcp: true, deadline.Token).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Failure, refused.Outcome); Assert.Null(refused.Revision);
    }

    private static async Task AnswerAsync(DnssecClientRequestProcessor processor, UdpClient udp, TcpListener listener, bool tcp, CancellationToken token)
    {
        if (!tcp)
        {
            var request = await udp.ReceiveAsync(token).ConfigureAwait(true);
            var reply = await processor.ProcessAsync(request.Buffer, request.RemoteEndPoint.Address.GetAddressBytes(), tcp: false, token).ConfigureAwait(true);
            Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, reply.Outcome); Assert.Null(reply.Revision);
            await udp.SendAsync(reply.GetMessage(), request.RemoteEndPoint, token).ConfigureAwait(true); return;
        }
        using var client = await listener.AcceptTcpClientAsync(token).ConfigureAwait(true);
        var peer = Assert.IsType<IPEndPoint>(client.Client.RemoteEndPoint);
        var stream = client.GetStream(); await using var streamLifetime = stream.ConfigureAwait(false);
        var requestBytes = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
        var result = await processor.ProcessAsync(requestBytes, peer.Address.GetAddressBytes(), tcp: true, token).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, result.Outcome); Assert.Null(result.Revision);
        await DnssecUpstreamFixture.SendFrameAsync(stream, result.GetMessage(), token).ConfigureAwait(true);
    }

    private static async Task<byte[]> QueryAsync(DnsServerEndpoint endpoint, byte[] request, bool tcp, CancellationToken token)
    {
        var address = new IPAddress(endpoint.GetAddress());
        if (!tcp)
        {
            using var client = new UdpClient(address.AddressFamily); client.Connect(address, endpoint.Port);
            await client.SendAsync(request, token).ConfigureAwait(true); return (await client.ReceiveAsync(token).ConfigureAwait(true)).Buffer;
        }
        using var peer = new TcpClient(address.AddressFamily); await peer.ConnectAsync(address, endpoint.Port, token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(false);
        await DnssecUpstreamFixture.SendFrameAsync(stream, request, token).ConfigureAwait(true);
        return await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
    }

    private sealed class FixedClock : TimeProvider
    {
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
