using System.Net.Sockets;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class AnchorRefreshTimingTransportTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    public async Task OnlyActualAcknowledgedWireProofPublishesTimingAndRecoveryInventsNone(bool ipv6, bool tcpFallback, bool corrupt)
    {
        using var f = new AnchorRefreshWireFixture(); using var directory = new AnchorStorageDirectory();
        var root = Path.Combine(directory.Path, "anchors"); var id = Guid.NewGuid();
        var secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        using var store = FileAnchorCheckpointStore.Create(root, id, new DnssecTrustAnchorTracker(f.Origin, [f.Initial], f.Verifier, f.Clock), secret);
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var tcp = Tcp;
        var endpoint = DnssecUpstreamFixture.Endpoint(udp);
        var worker = Task.Run(() => ServeOnceAsync(f, udp, tcp, tcpFallback, corrupt, closure.Token), closure.Token);
        try
        {
            var client = new DnssecUpstreamClient(peer => peer.Equals(endpoint), TimeSpan.FromSeconds(3));
            var refresher = new DnssecAnchorRefresher(f.Origin, store, client, f.Verifier, endpoint, f.Clock);
            await using var refresherLifetime = refresher.ConfigureAwait(false);
            Assert.Null(refresher.CurrentTiming);
            Assert.Equal(corrupt ? DnssecAnchorRefreshOutcome.Refused : DnssecAnchorRefreshOutcome.Applied,
                await refresher.RefreshAsync(closure.Token).ConfigureAwait(true));
            Assert.Equal(corrupt ? 1 : 2, refresher.Current.Revision); Assert.Single(refresher.Current.Anchors);
            AssertTiming(refresher, f.Origin, corrupt);
            store.Dispose();
            using var recovered = FileAnchorCheckpointStore.Open(root, id, f.Origin, secret, corrupt ? 1 : 2, f.Verifier, f.Clock);
            Assert.Equal(corrupt ? 1 : 2, recovered.Tracker.GetStatus().Count);
            var restored = new DnssecAnchorRefresher(f.Origin, recovered, client, f.Verifier, endpoint, f.Clock);
            await using var restoredLifetime = restored.ConfigureAwait(false);
            Assert.Equal(corrupt ? 1 : 2, restored.Current.Revision); Assert.Null(restored.CurrentTiming);
        }
        finally
        {
            await closure.CancelAsync().ConfigureAwait(true);
            try { await worker.ConfigureAwait(true); }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static void AssertTiming(DnssecAnchorRefresher refresher, DnsName origin, bool corrupt)
    {
        if (corrupt)
        {
            Assert.Null(refresher.CurrentTiming);
        }
        else
        {
            var timing = Assert.IsType<DnssecAnchorRefreshTiming>(refresher.CurrentTiming);
            Assert.Equal(2, timing.Revision); Assert.Equal(origin, timing.Origin);
            Assert.Equal(3600u, timing.Proof.OriginalTtl); Assert.Equal(TimeSpan.FromSeconds(9900), timing.Proof.SignatureExpirationInterval);
            Assert.Equal(TimeSpan.FromHours(1), timing.Proof.QueryInterval); Assert.Equal(TimeSpan.FromHours(1), timing.Proof.RetryInterval);
            Assert.InRange(timing.RemainingQueryInterval, TimeSpan.Zero, TimeSpan.FromHours(1));
        }
    }

    private static async Task ServeOnceAsync(AnchorRefreshWireFixture fixture, UdpClient udp, TcpListener tcp,
        bool tcpFallback, bool corrupt, CancellationToken token)
    {
        var packet = await udp.ReceiveAsync(token).ConfigureAwait(true);
        var query = DnsMessageCodec.DecodeQuery(packet.Buffer);
        Assert.Equal(new DnsQuestion(fixture.Origin, 48, 1), query.Question); Assert.True(query.DnssecOk);
        if (!tcpFallback)
        {
            await udp.SendAsync(AnchorRefreshWireFixture.Reply(packet.Buffer, fixture.Records(corrupt: corrupt)), packet.RemoteEndPoint, token).ConfigureAwait(true);
        }
        else
        {
            var truncated = AnchorRefreshWireFixture.Reply(packet.Buffer, []); truncated[2] |= 2;
            await udp.SendAsync(truncated, packet.RemoteEndPoint, token).ConfigureAwait(true);
            using var peer = await tcp.AcceptTcpClientAsync(token).ConfigureAwait(true);
            var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(false);
            var frame = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
            Assert.Equal(packet.Buffer, frame);
            await DnssecUpstreamFixture.SendFrameAsync(stream, AnchorRefreshWireFixture.Reply(frame, fixture.Records(corrupt: corrupt)), token).ConfigureAwait(true);
        }
    }
}
