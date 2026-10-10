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

public sealed class AnchorPollingTransportTests
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
    public async Task ScheduledFreshWireProofCommitsNativeCheckpointBeforeEpochCacheReplacement(bool ipv6, bool fallback, bool corrupt)
    {
        using var fixture = new AnchorRefreshWireFixture(); using var directory = new AnchorStorageDirectory();
        var clock = new AnchorPollingWireClock(); var secret = RandomNumberGenerator.GetBytes(32); var identity = Guid.NewGuid();
        var root = Path.Combine(directory.Path, "anchors");
        using var store = FileAnchorCheckpointStore.Create(root, identity,
            new DnssecTrustAnchorTracker(fixture.Origin, [fixture.Initial], fixture.Verifier, clock), secret);
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var tcp = Tcp;
        var endpoint = DnssecUpstreamFixture.Endpoint(udp);
        var client = new DnssecUpstreamClient(peer => peer.Equals(endpoint), TimeSpan.FromSeconds(3));
        var refresher = new DnssecAnchorRefresher(fixture.Origin, store, client, fixture.Verifier, endpoint, clock);
        await using var refresherLifetime = refresher.ConfigureAwait(false);
        var resolver = new DnssecTrustEpochResolver(refresher, client, fixture.Verifier, [endpoint], new DnssecTrustEpochPolicy());
        await using var resolverLifetime = resolver.ConfigureAwait(false);
        var worker = ServeAsync(fixture, udp, tcp, fallback, corrupt, closure.Token);
        try
        {
            await ExerciseAsync(store, refresher, resolver, clock, corrupt, closure.Token).ConfigureAwait(true);
            store.Dispose();
            using var recovered = FileAnchorCheckpointStore.Open(root, identity, fixture.Origin, secret, corrupt ? 1 : 2, fixture.Verifier, clock);
            Assert.Equal(corrupt ? 1 : 2, recovered.Revision);
            Assert.Equal(corrupt ? 1 : 0, recovered.Tracker.GetTrustAnchors().Count);
        }
        finally
        {
            await closure.CancelAsync().ConfigureAwait(true);
            try { await worker.ConfigureAwait(true); }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static async Task ExerciseAsync(FileAnchorCheckpointStore store,
        DnssecAnchorRefresher refresher, DnssecTrustEpochResolver resolver, AnchorPollingWireClock clock, bool corrupt, CancellationToken token)
    {
        var question = new DnsQuestion(DnsName.Parse("www.example."), 1, 1);
        var original = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, original.Outcome); Assert.Single(original.Answers); Assert.Equal(7200u, original.AuthenticatedTtl);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true)).Outcome);
        var poller = new DnssecAnchorPoller(refresher, new DnssecAnchorPollingPolicy(TimeSpan.FromHours(1), TimeSpan.FromHours(1), 1), clock);
        await using var pollerLifetime = poller.ConfigureAwait(false);
        await clock.Created.Task.WaitAsync(AnchorRefreshWireFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, store.Revision); clock.Set(TimeSpan.FromHours(1));
        await poller.Completion.WaitAsync(AnchorRefreshWireFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, poller.Statistics.Attempts); Assert.Equal(corrupt ? 0 : 1, poller.Statistics.Applied);
        Assert.Equal(corrupt ? 1 : 0, poller.Statistics.Refused); Assert.Equal(0, clock.ActiveTimers);
        var after = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
        Assert.Equal(corrupt ? DnssecResolutionOutcome.Authenticated : DnssecResolutionOutcome.Failure, after.Outcome);
        Assert.Equal(corrupt ? 1 : 2, resolver.Statistics.Revision); Assert.Equal(corrupt ? 1 : 0, resolver.Statistics.Anchors);
        Assert.Equal(corrupt ? 1 : 2, store.Revision); Assert.Null(after.UnsignedDelegation);
        if (!corrupt) { Assert.Empty(after.Answers); Assert.Empty(after.Authority); }
        else { Assert.InRange(Assert.Single(after.Answers).Ttl, 1u, 3600u); }
    }

    private static DnsRecord[] InitialRecords(AnchorRefreshWireFixture fixture)
    {
        DnsRecord[] records = [DnssecKeys.CreateDnskey(fixture.Origin, 7200, fixture.Key.GetPublicKey()),
            DnssecKeys.CreateDnskey(fixture.Origin, 7200, fixture.Next.GetPublicKey())];
        return [.. records, DnssecRrsetSigner.Sign(records, fixture.Initial, fixture.Key, fixture.Verifier, new DnssecSignatureWindow(99, 10_000))];
    }

    private static async Task ServeAsync(AnchorRefreshWireFixture fixture, UdpClient udp, TcpListener tcp,
        bool fallback, bool corrupt, CancellationToken token)
    {
        for (var index = 0; index < 3; index++)
        {
            var packet = await udp.ReceiveAsync(token).ConfigureAwait(true);
            var query = DnsMessageCodec.DecodeQuery(packet.Buffer);
            Assert.True(query.DnssecOk); Assert.Equal(16, query.Flags & 16);
            DnsRecord[] records;
            if (index == 1)
            {
                var question = new DnsQuestion(DnsName.Parse("www.example."), 1, 1); Assert.Equal(question, query.Question);
                var data = new DnsRecord(question.Name, 1, 7200, [192, 0, 2, 1]);
                records = [data, DnssecRrsetSigner.Sign([data], fixture.Initial, fixture.Key, fixture.Verifier, new DnssecSignatureWindow(99, 10_000))];
            }
            else
            {
                Assert.Equal(new DnsQuestion(fixture.Origin, 48, 1), query.Question);
                records = index == 2 ? fixture.Records(revoke: true, corrupt: corrupt) : InitialRecords(fixture);
            }
            if (!fallback)
            {
                await udp.SendAsync(AnchorRefreshWireFixture.Reply(packet.Buffer, records), packet.RemoteEndPoint, token).ConfigureAwait(true);
            }
            else
            {
                var truncated = AnchorRefreshWireFixture.Reply(packet.Buffer, []); truncated[2] |= 2;
                await udp.SendAsync(truncated, packet.RemoteEndPoint, token).ConfigureAwait(true);
                using var peer = await tcp.AcceptTcpClientAsync(token).ConfigureAwait(true);
                var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(false);
                var frame = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true); Assert.Equal(packet.Buffer, frame);
                await DnssecUpstreamFixture.SendFrameAsync(stream, AnchorRefreshWireFixture.Reply(frame, records), token).ConfigureAwait(true);
            }
        }
    }
}
