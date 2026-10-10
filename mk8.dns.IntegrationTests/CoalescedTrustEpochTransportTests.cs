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

public sealed class CoalescedTrustEpochTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task SharedWireWorkAndCacheStayWithinOneAcknowledgedNativeStoredRevision(bool ipv6, bool tcpFallback)
    {
        using var f = new AnchorRefreshWireFixture(); using var directory = new AnchorStorageDirectory();
        var secret = RandomNumberGenerator.GetBytes(32);
        try { await RunAsync(f, directory, secret, ipv6, tcpFallback).ConfigureAwait(true); }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static async Task RunAsync(AnchorRefreshWireFixture f, AnchorStorageDirectory directory, byte[] secret, bool ipv6, bool fallback)
    {
        using var store = FileAnchorCheckpointStore.Create(Path.Combine(directory.Path, "anchors"), Guid.NewGuid(),
            new DnssecTrustAnchorTracker(f.Origin, [f.Initial], f.Verifier, f.Clock), secret);
        using var closure = new CancellationTokenSource(AnchorRefreshWireFixture.Timeout);
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var tcp = Tcp;
        var endpoint = DnssecUpstreamFixture.Endpoint(udp);
        var client = new DnssecUpstreamClient(peer => peer.Equals(endpoint), TimeSpan.FromSeconds(3));
        var held = new HeldUpstream(client);
        var refresher = new DnssecAnchorRefresher(f.Origin, store, client, f.Verifier, endpoint, f.Clock);
        await using var refresherLifetime = refresher.ConfigureAwait(true);
        var resolver = DnssecTrustEpochResolver.CreateWithCoalescing(refresher, held, f.Verifier, [endpoint],
            new DnssecTrustEpochPolicy(maximumActiveRequests: 4), new DnssecWorkPolicy(maximumWorkers: 1), f.Clock);
        await using var resolverLifetime = resolver.ConfigureAwait(true);
        await Task.WhenAll(ServeAsync(f, udp, tcp, fallback, closure.Token),
            ExerciseAsync(resolver, refresher, store, held, closure)).ConfigureAwait(true);
    }

    private static async Task ExerciseAsync(DnssecTrustEpochResolver resolver, DnssecAnchorRefresher refresher,
        FileAnchorCheckpointStore store, HeldUpstream source, CancellationTokenSource closure)
    {
        var token = closure.Token; var question = new DnsQuestion(DnsName.Parse("www.example."), 1, 1);
        try
        {
            var first = resolver.ResolveDnssecAsync(question, token).AsTask();
            await source.Entered.Task.WaitAsync(token).ConfigureAwait(true);
            var second = resolver.ResolveDnssecAsync(question, token).AsTask();
            try
            {
                while (resolver.CurrentWorkStatistics?.Coalesced != 1) await Task.Delay(1, token).ConfigureAwait(true);
                Assert.Equal(1, resolver.ActiveWorkers); Assert.Equal(2, resolver.Statistics.ActiveRequests);
            }
            finally { source.Released.TrySetResult(); }
            var results = await Task.WhenAll(first, second).WaitAsync(token).ConfigureAwait(true);
            Assert.All(results, result => Assert.Equal(1, Assert.Single(result.Answers).GetData()[3]));
            Assert.All(results, result => Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome));
            var calls = source.Calls;
            Assert.Equal(1, Assert.Single((await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true)).Answers).GetData()[3]);
            Assert.Equal(calls, source.Calls);
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await refresher.RefreshAsync(token).ConfigureAwait(true));
            var newer = await resolver.ResolveDnssecAsync(question, token).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, newer.Outcome);
            Assert.Equal(2, Assert.Single(newer.Answers).GetData()[3]); Assert.Equal(2, store.Revision);
            Assert.Equal(2, resolver.Statistics.Revision); Assert.Equal(calls + 2, source.Calls);
            Assert.Equal(0, resolver.ActiveWorkers); Assert.Equal(0, resolver.Statistics.RetiredProfiles);
        }
        finally { source.Released.TrySetResult(); await closure.CancelAsync().ConfigureAwait(true); }
    }

    private static async Task ServeAsync(AnchorRefreshWireFixture f, UdpClient udp, TcpListener tcp, bool fallback, CancellationToken token)
    {
        for (var index = 0; index < 5; index++)
        {
            var packet = await udp.ReceiveAsync(token).ConfigureAwait(true);
            var query = DnsMessageCodec.DecodeQuery(packet.Buffer);
            var question = Assert.IsType<DnsQuestion>(query.Question);
            Assert.True(query.DnssecOk); Assert.Equal(16, query.Flags & 16);
            DnsRecord[] records;
            if (index is 1 or 4)
            {
                Assert.Equal(new DnsQuestion(DnsName.Parse("www.example."), 1, 1), question);
                // Reserved documentation bytes vary only between controlled acknowledged cohorts.
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
                var frame = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
                Assert.Equal(packet.Buffer, frame);
                await DnssecUpstreamFixture.SendFrameAsync(stream, AnchorRefreshWireFixture.Reply(frame, records), token).ConfigureAwait(true);
            }
        }
    }

    private sealed class HeldUpstream(IDnssecUpstream source) : IDnssecUpstream
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Released { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                Entered.TrySetResult(); await Released.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            return await source.ExchangeDnssecAsync(question, server, cancellationToken).ConfigureAwait(false);
        }
    }
}
