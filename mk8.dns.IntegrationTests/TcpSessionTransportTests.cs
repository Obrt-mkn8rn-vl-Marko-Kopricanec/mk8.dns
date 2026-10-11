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

public sealed class TcpSessionTransportTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OwnedTcpConnectionCarriesTwoPipelinedQuestionsThroughFiniteAuthenticatedSession(bool ipv6)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false);
        var root = new OnlineDnssecWireFixture.Node(ipv6, forceTcp: true, corrupt: false, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, forceTcp: true, corrupt: false, deadline.Token); await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var clock = new SessionClock();
        var tracker = new DnssecTrustAnchorTracker(zones.Anchor.Origin, [zones.Anchor.Record], OnlineDnssecWireFixture.Verifier, clock);
        var store = new TrustEpochLifetimeWireFixture.PinnedStore(new DnssecStoredAnchorCheckpoint(tracker.Origin, 1, tracker.CreateCheckpoint()));
        var refresher = new DnssecAnchorRefresher(tracker.Origin, store, upstream, OnlineDnssecWireFixture.Verifier, root.Server, clock);
        await using var refreshLifetime = refresher.ConfigureAwait(true);
        var source = DnssecTrustEpochResolver.CreateWithClientProof(refresher, upstream, OnlineDnssecWireFixture.Verifier,
            [root.Server], new DnssecTrustEpochPolicy(), child.Server.Port); await using var sourceLifetime = source.ConfigureAwait(true);
        var address = root.Server.GetAddress();
        var processor = DnssecClientRequestProcessor.CreateWithCompleteTcpAnswers(source,
            new DnssecClientAccessPolicy([new DnssecClientNetwork(address, address.Length * 8)], authenticatedDataAllowed: true));
        await using var processorLifetime = processor.ConfigureAwait(true);
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var listener = Tcp;
        try { await ExerciseAsync(processor, root, address, udp, listener, ipv6, deadline).ConfigureAwait(true); }
        finally { await deadline.CancelAsync().ConfigureAwait(true); }
        Assert.Equal(0, processor.ActiveRequests); Assert.Equal(0, source.Statistics.ActiveRequests);
    }

    private static async Task ExerciseAsync(DnssecClientRequestProcessor processor, OnlineDnssecWireFixture.Node root,
        byte[] address, UdpClient udp, TcpListener listener, bool ipv6, CancellationTokenSource deadline)
    {
        var token = deadline.Token;
        var serving = ServeAsync(processor, listener, token);
        try
        {
            using var client = new TcpClient(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
            await client.ConnectAsync(new IPAddress(address), DnssecUpstreamFixture.Endpoint(udp).Port, token).ConfigureAwait(true);
            var stream = client.GetStream(); await using var streamLifetime = stream.ConfigureAwait(false);
            var questions = new[] { new DnsQuestion(DnsName.Parse("alias.example."), 1, 1), new DnsQuestion(DnsName.Parse("missing.child.example."), 1, 1) };
            for (var index = 0; index < questions.Length; index++)
            {
                var request = UpstreamMessageCodec.EncodeDnssecQuery((ushort)(90 + index), questions[index]);
                BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0100);
                await DnssecUpstreamFixture.SendFrameAsync(stream, request, token).ConfigureAwait(true);
            }
            for (var index = 0; index < questions.Length; index++)
            {
                var frame = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
                var reply = UpstreamMessageCodec.DecodeDnssecResponse(frame, (ushort)(90 + index), questions[index], root.Server);
                Assert.False(reply.Truncated); Assert.Equal(index == 0 ? 0 : 3, reply.Evidence.ResponseCode);
                Assert.True(reply.Evidence.AuthenticatedDataObserved); Assert.Contains(reply.Evidence.Answers.Concat(reply.Evidence.Authority), record => record.Type == 46);
                Assert.DoesNotContain(reply.Evidence.Answers.Concat(reply.Evidence.Authority), record => record.Type is 2 or 43 or 48);
            }
            var result = await serving.WaitAsync(TimeSpan.FromSeconds(15), TimeProvider.System, token).ConfigureAwait(true);
            Assert.Equal(DnssecClientTcpSessionOutcome.MessageLimit, result.Outcome); Assert.Equal(2, result.MessagesRead); Assert.Equal(2, result.RepliesWritten);
        }
        finally { await deadline.CancelAsync().ConfigureAwait(true); await serving.ConfigureAwait(true); }
    }

    private static async Task<DnssecClientTcpSessionResult> ServeAsync(DnssecClientRequestProcessor processor, TcpListener listener, CancellationToken token)
    {
        using var client = await listener.AcceptTcpClientAsync(token).ConfigureAwait(true);
        var peer = Assert.IsType<IPEndPoint>(client.Client.RemoteEndPoint);
        var stream = client.GetStream(); await using var streamLifetime = stream.ConfigureAwait(false);
        var session = new DnssecClientTcpSession(processor, stream, peer.Address.GetAddressBytes(), 2); await using var sessionLifetime = session.ConfigureAwait(true);
        return await session.RunAsync(token).ConfigureAwait(true);
    }

    private sealed class SessionClock : TimeProvider
    {
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
