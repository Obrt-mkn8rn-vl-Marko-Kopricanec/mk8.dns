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

public sealed class AnchorRetentionTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task RetainedJournalBeyondOldLimitKeepsCacheThenAdoptsFreshAcknowledgedWireTrust(bool ipv6, bool fallback)
    {
        using var f = new AnchorRefreshWireFixture(); using var directory = new AnchorStorageDirectory();
        var secret = RandomNumberGenerator.GetBytes(32);
        try { await RunAsync(f, directory, secret, ipv6, fallback).ConfigureAwait(true); }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static async Task RunAsync(AnchorRefreshWireFixture f, AnchorStorageDirectory directory,
        byte[] secret, bool ipv6, bool fallback)
    {
        using var store = FileAnchorCheckpointStore.CreateWithRetention(Path.Combine(directory.Path, "anchors"),
            Guid.NewGuid(), new DnssecTrustAnchorTracker(f.Origin, [f.Initial], f.Verifier, f.Clock), secret);
        for (long revision = 1; revision < 256; revision++) Assert.Equal(revision + 1, store.Save(revision));
        Assert.Equal(256, store.Retain(256, 256, 1)); Assert.Equal(257, store.Save(256));
        using var closure = new CancellationTokenSource(AnchorRefreshWireFixture.Timeout);
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var tcp = Tcp;
        var endpoint = DnssecUpstreamFixture.Endpoint(udp);
        var client = new DnssecUpstreamClient(peer => peer.Equals(endpoint), TimeSpan.FromSeconds(3));
        var counted = new CountedUpstream(client);
        var refresher = new DnssecAnchorRefresher(f.Origin, store, client, f.Verifier, endpoint, f.Clock);
        await using var refresherLifetime = refresher.ConfigureAwait(true);
        var resolver = DnssecTrustEpochResolver.CreateWithCoalescing(refresher, counted, f.Verifier, [endpoint],
            new DnssecTrustEpochPolicy(), new DnssecWorkPolicy(maximumWorkers: 1), f.Clock);
        await using var resolverLifetime = resolver.ConfigureAwait(true);
        await Task.WhenAll(ServeAsync(f, udp, tcp, fallback, closure.Token),
            ExerciseAsync(store, refresher, resolver, counted, closure)).ConfigureAwait(true);
    }

    private static async Task ExerciseAsync(FileAnchorCheckpointStore store, DnssecAnchorRefresher refresher,
        DnssecTrustEpochResolver resolver, CountedUpstream source, CancellationTokenSource closure)
    {
        var question = new DnsQuestion(DnsName.Parse("www.example."), 1, 1); var token = closure.Token;
        try
        {
            var first = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, first.Outcome); Assert.Equal(1, Assert.Single(first.Answers).GetData()[3]);
            Assert.Equal(257, resolver.Statistics.Revision); Assert.Equal(2, source.Calls);
            var saved = ((IDnssecAnchorCheckpointStore)store).ReadCommitted().GetCheckpoint();
            Assert.Equal(257, store.Retain(257, 257, 1, token));
            Assert.Equal(257, store.Revision); Assert.Equal(saved, ((IDnssecAnchorCheckpointStore)store).ReadCommitted().GetCheckpoint());
            var hit = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
            Assert.Equal(1, Assert.Single(hit.Answers).GetData()[3]); Assert.Equal(2, source.Calls);
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await refresher.RefreshAsync(token).ConfigureAwait(true));
            Assert.Equal(258, store.Revision);
            var fresh = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome); Assert.Equal(2, Assert.Single(fresh.Answers).GetData()[3]);
            Assert.Equal(258, resolver.Statistics.Revision); Assert.Equal(4, source.Calls);
            Assert.Equal(257, store.FirstRetainedRevision); Assert.Equal(0, resolver.Statistics.RetiredProfiles);
        }
        finally { await closure.CancelAsync().ConfigureAwait(true); }
    }

    private static async Task ServeAsync(AnchorRefreshWireFixture f, UdpClient udp, TcpListener tcp,
        bool fallback, CancellationToken token)
    {
        for (var index = 0; index < 5; index++)
        {
            var packet = await udp.ReceiveAsync(token).ConfigureAwait(true);
            var query = DnsMessageCodec.DecodeQuery(packet.Buffer); var question = Assert.IsType<DnsQuestion>(query.Question);
            Assert.True(query.DnssecOk); Assert.Equal(16, query.Flags & 16);
            DnsRecord[] records;
            if (index is 1 or 4)
            {
                Assert.Equal(new DnsQuestion(DnsName.Parse("www.example."), 1, 1), question);
                // Reserved documentation data distinguishes the two controlled trust cohorts.
                var data = new DnsRecord(question.Name, 1, 300, [192, 0, 2, index == 1 ? (byte)1 : (byte)2]);
                records = [data, DnssecRrsetSigner.Sign([data], f.Initial, f.Key, f.Verifier, new DnssecSignatureWindow(99, 10_000))];
            }
            else { Assert.Equal(new DnsQuestion(f.Origin, 48, 1), question); records = f.Records(); }
            if (!fallback)
            {
                await udp.SendAsync(AnchorRefreshWireFixture.Reply(packet.Buffer, records), packet.RemoteEndPoint, token).ConfigureAwait(true);
            }
            else
            {
                var truncated = AnchorRefreshWireFixture.Reply(packet.Buffer, []); truncated[2] |= 2;
                await udp.SendAsync(truncated, packet.RemoteEndPoint, token).ConfigureAwait(true);
                using var peer = await tcp.AcceptTcpClientAsync(token).ConfigureAwait(true);
                var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
                var request = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
                Assert.Equal(packet.Buffer, request);
                await DnssecUpstreamFixture.SendFrameAsync(stream, AnchorRefreshWireFixture.Reply(request, records), token).ConfigureAwait(true);
            }
        }
    }

    private sealed class CountedUpstream(IDnssecUpstream source) : IDnssecUpstream
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken token)
        {
            Interlocked.Increment(ref calls); return source.ExchangeDnssecAsync(question, server, token);
        }
    }
}
