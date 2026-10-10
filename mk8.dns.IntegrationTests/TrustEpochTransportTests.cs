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

public sealed class TrustEpochTransportTests
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
    public async Task AcknowledgedNativeStoredRevocationReplacesActualWireCacheOnlyAfterValidProof(bool ipv6, bool tcpFallback, bool corrupt)
    {
        using var f = new AnchorRefreshWireFixture(); using var directory = new AnchorStorageDirectory();
        var secret = RandomNumberGenerator.GetBytes(32); var identity = Guid.NewGuid();
        using var store = FileAnchorCheckpointStore.Create(Path.Combine(directory.Path, "anchors"), identity,
            new DnssecTrustAnchorTracker(f.Origin, [f.Initial], f.Verifier, f.Clock), secret);
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var tcp = Tcp;
        var endpoint = DnssecUpstreamFixture.Endpoint(udp);
        var client = new DnssecUpstreamClient(peer => peer.Equals(endpoint), TimeSpan.FromSeconds(3));
        var refresher = new DnssecAnchorRefresher(f.Origin, store, client, f.Verifier, endpoint, f.Clock);
        await using var refresherLifetime = refresher.ConfigureAwait(false);
        var resolver = new DnssecTrustEpochResolver(refresher, client, f.Verifier, [endpoint], new DnssecTrustEpochPolicy());
        await using var resolverLifetime = resolver.ConfigureAwait(false);
        var question = new DnsQuestion(DnsName.Parse("www.example."), 1, 1);
        try
        {
            await Task.WhenAll(ServeAsync(f, udp, tcp, tcpFallback, corrupt, closure.Token),
                ExerciseAndCancelAsync(resolver, refresher, store, question, corrupt, closure)).ConfigureAwait(true);
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static async Task ExerciseAndCancelAsync(DnssecTrustEpochResolver resolver, DnssecAnchorRefresher refresher,
        FileAnchorCheckpointStore store, DnsQuestion question, bool corrupt, CancellationTokenSource closure)
    {
        var token = closure.Token;
        try
        {
            var original = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, original.Outcome);
            var originalRecord = Assert.Single(original.Answers);
            var hit = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
            Assert.Equal(originalRecord.GetData(), Assert.Single(hit.Answers).GetData());
            Assert.Equal(corrupt ? DnssecAnchorRefreshOutcome.Refused : DnssecAnchorRefreshOutcome.Applied,
                await refresher.RefreshAsync(token).ConfigureAwait(true));
            var after = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
            Assert.Equal(corrupt ? DnssecResolutionOutcome.Authenticated : DnssecResolutionOutcome.Failure, after.Outcome);
            Assert.Equal(corrupt ? 1 : 2, resolver.Statistics.Revision);
            Assert.Equal(corrupt ? 1 : 0, resolver.Statistics.Entries); Assert.Equal(corrupt ? 1 : 0, resolver.Statistics.Anchors);
            Assert.Equal(corrupt ? 1 : 2, store.Revision);
            Assert.Null(after.UnsignedDelegation); Assert.Empty(after.Authority);
            if (!corrupt) Assert.Empty(after.Answers);
        }
        finally { await closure.CancelAsync().ConfigureAwait(true); }
    }

    private static async Task ServeAsync(AnchorRefreshWireFixture fixture, UdpClient udp, TcpListener tcp,
        bool fallback, bool corrupt, CancellationToken token)
    {
        for (var index = 0; index < 3; index++)
        {
            var packet = await udp.ReceiveAsync(token).ConfigureAwait(true);
            var query = DnsMessageCodec.DecodeQuery(packet.Buffer);
            var question = Assert.IsType<DnsQuestion>(query.Question);
            Assert.True(query.DnssecOk); Assert.Equal(16, query.Flags & 16);
            DnsRecord[] records;
            if (index != 1)
            {
                Assert.Equal(new DnsQuestion(fixture.Origin, 48, 1), query.Question);
                records = fixture.Records(revoke: index == 2, corrupt: index == 2 && corrupt);
            }
            else
            {
                Assert.Equal(new DnsQuestion(DnsName.Parse("www.example."), 1, 1), query.Question);
                var data = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 1]);
                records = [data, DnssecRrsetSigner.Sign([data], fixture.Initial, fixture.Key, fixture.Verifier, new DnssecSignatureWindow(99, 10_000))];
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
                var frame = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
                Assert.Equal(packet.Buffer, frame);
                await DnssecUpstreamFixture.SendFrameAsync(stream, AnchorRefreshWireFixture.Reply(frame, records), token).ConfigureAwait(true);
            }
        }
    }
}
