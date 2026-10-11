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

public sealed class NativeRecursiveHostTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task OwnedHostServesActualAcquiredAliasAndDenialOnBothFamilies(bool ipv6, bool tcp)
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
        var address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        var bytes = address.GetAddressBytes();
        var host = await DnssecClientHost.CreateAsync(refresher, upstream, OnlineDnssecWireFixture.Verifier,
            [root.Server], new DnssecTrustEpochPolicy(),
            new DnssecClientAccessPolicy([new DnssecClientNetwork(bytes, bytes.Length * 8)], authenticatedDataAllowed: true),
            new IPEndPoint(address, 0), new DnssecWorkPolicy(), TimeProvider.System, child.Server.Port,
            udpWorkers: 2, maximumTcpConnections: 2).ConfigureAwait(true);
        await using var hostLifetime = host.ConfigureAwait(true);
        var running = host.RunAsync(deadline.Token);
        var bound = await host.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        try { await ExerciseAsync(root, child, bound, clock, tcp, deadline.Token).ConfigureAwait(true); }
        finally { await host.DisposeAsync().ConfigureAwait(true); await deadline.CancelAsync().ConfigureAwait(true); }
        await running.ConfigureAwait(true);
        Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers);
        Assert.Equal(0, host.ActiveTcpConnections);
    }

    private static async Task ExerciseAsync(OnlineDnssecWireFixture.Node root, OnlineDnssecWireFixture.Node child,
        IPEndPoint bound, MessageClock clock, bool tcp, CancellationToken token)
    {
        foreach (var name in new[] { "alias.example.", "missing.child.example." })
        {
            var question = new DnsQuestion(DnsName.Parse(name), 1, 1); var before = -1;
            foreach (var dnssecOk in new[] { false, true })
            {
                var request = UpstreamMessageCodec.EncodeDnssecQuery(19, question);
                BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0100);
                if (!dnssecOk) request[^4] = 0;
                var reply = await QueryAsync(bound, request, tcp, token).ConfigureAwait(true);
                var server = new DnsServerEndpoint(bound.Address.GetAddressBytes(), (ushort)bound.Port);
                var decoded = UpstreamMessageCodec.DecodeDnssecResponse(reply, 19, question, server);
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

    private static async Task<byte[]> QueryAsync(IPEndPoint endpoint, byte[] packet, bool tcp, CancellationToken token)
    {
        if (!tcp)
        {
            using var client = new UdpClient(endpoint.AddressFamily); client.Connect(endpoint);
            _ = await client.SendAsync(packet, token).ConfigureAwait(true);
            return (await client.ReceiveAsync(token).ConfigureAwait(true)).Buffer;
        }
        using var peer = new TcpClient(endpoint.AddressFamily);
        await peer.ConnectAsync(endpoint, token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
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
