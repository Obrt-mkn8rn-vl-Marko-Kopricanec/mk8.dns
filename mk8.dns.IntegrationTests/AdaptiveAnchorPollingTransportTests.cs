using System.Net.Sockets;
using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class AdaptiveAnchorPollingTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ActualWireAcknowledgementChangesCadenceAndExpiredNextProofCannotCommit(bool ipv6, bool fallback)
    {
        using var fixture = new AnchorRefreshWireFixture(); using var directory = new AnchorStorageDirectory();
        var clock = new AdaptiveAnchorWireClock(); var secret = RandomNumberGenerator.GetBytes(32); var identity = Guid.NewGuid();
        var root = Path.Combine(directory.Path, "anchors");
        using var store = FileAnchorCheckpointStore.Create(root, identity,
            new DnssecTrustAnchorTracker(fixture.Origin, [fixture.Initial], fixture.Verifier, clock), secret);
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var tcp = Tcp;
        var endpoint = DnssecUpstreamFixture.Endpoint(udp);
        var client = new DnssecUpstreamClient(peer => peer.Equals(endpoint), TimeSpan.FromSeconds(3));
        var refresher = new DnssecAnchorRefresher(fixture.Origin, store, client, fixture.Verifier, endpoint, clock);
        await using var refresherLifetime = refresher.ConfigureAwait(false);
        var worker = ServeAsync(fixture, udp, tcp, fallback, closure.Token);
        try
        {
            await ExerciseAsync(refresher, store, clock).ConfigureAwait(true);
            store.Dispose();
            using var recovered = FileAnchorCheckpointStore.Open(root, identity, fixture.Origin, secret, 2, fixture.Verifier, clock);
            Assert.Equal(2, recovered.Revision); Assert.Single(recovered.Tracker.GetTrustAnchors());
        }
        finally
        {
            await closure.CancelAsync().ConfigureAwait(true);
            try { await worker.ConfigureAwait(true); }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static async Task ExerciseAsync(DnssecAnchorRefresher refresher, FileAnchorCheckpointStore store, AdaptiveAnchorWireClock clock)
    {
        var poller = DnssecAnchorPoller.CreateWithAuthenticatedTiming(refresher,
            new DnssecAnchorPollingPolicy(TimeSpan.FromHours(2), TimeSpan.FromHours(1), 2), clock);
        await using var pollerLifetime = poller.ConfigureAwait(false);
        Assert.Equal(TimeSpan.FromHours(2), await clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(1, store.Revision); clock.Set(TimeSpan.FromHours(2));
        Assert.Equal(TimeSpan.FromHours(1), await clock.NextTimerAsync().ConfigureAwait(true));
        Assert.Equal(2, store.Revision); Assert.Equal(1, poller.Statistics.Applied);
        clock.Set(TimeSpan.FromHours(3));
        await poller.Completion.WaitAsync(AnchorRefreshWireFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, poller.Statistics.Attempts); Assert.Equal(1, poller.Statistics.Refused);
        Assert.Equal(2, store.Revision); Assert.Equal(0, clock.ActiveTimers);
    }

    private static async Task ServeAsync(AnchorRefreshWireFixture fixture, UdpClient udp, TcpListener tcp, bool fallback, CancellationToken token)
    {
        for (var index = 0; index < 2; index++)
        {
            var packet = await udp.ReceiveAsync(token).ConfigureAwait(true); var query = DnsMessageCodec.DecodeQuery(packet.Buffer);
            Assert.Equal(new DnsQuestion(fixture.Origin, 48, 1), query.Question); Assert.True(query.DnssecOk);
            if (!fallback)
            {
                await udp.SendAsync(AnchorRefreshWireFixture.Reply(packet.Buffer, fixture.Records()), packet.RemoteEndPoint, token).ConfigureAwait(true);
            }
            else
            {
                var truncated = AnchorRefreshWireFixture.Reply(packet.Buffer, []); truncated[2] |= 2;
                await udp.SendAsync(truncated, packet.RemoteEndPoint, token).ConfigureAwait(true);
                using var peer = await tcp.AcceptTcpClientAsync(token).ConfigureAwait(true); var stream = peer.GetStream();
                await using var streamLifetime = stream.ConfigureAwait(false);
                var frame = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true); Assert.Equal(packet.Buffer, frame);
                await DnssecUpstreamFixture.SendFrameAsync(stream, AnchorRefreshWireFixture.Reply(frame, fixture.Records()), token).ConfigureAwait(true);
            }
        }
    }
}
