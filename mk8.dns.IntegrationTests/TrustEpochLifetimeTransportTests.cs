using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class TrustEpochLifetimeTransportTests
{
    [Theory]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    public async Task ActualAcquiredBootstrapExpiryOrRemainingCacheLifetimeIncludesEarlierFailedPinTime(bool ipv6, bool tcpFallback, bool expired)
    {
        using var fixture = new TrustEpochLifetimeWireFixture();
        using var closure = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var (Udp, Tcp) = DnssecUpstreamFixture.BindPair(ipv6); using var udp = Udp; using var tcp = Tcp;
        var endpoint = DnssecUpstreamFixture.Endpoint(udp);
        var client = new DnssecUpstreamClient(peer => peer.Equals(endpoint), TimeSpan.FromSeconds(3));
        var refresher = new DnssecAnchorRefresher(fixture.Origin, fixture.Store, client, fixture.Native, endpoint, fixture.Clock);
        await using var refresherLifetime = refresher.ConfigureAwait(false);
        fixture.SelectPins(refresher.Current);
        var resolver = new DnssecTrustEpochResolver(refresher, client, fixture.Verifier, [endpoint], new DnssecTrustEpochPolicy());
        await using var resolverLifetime = resolver.ConfigureAwait(false);
        await Task.WhenAll(ServeAsync(fixture, udp, tcp, tcpFallback, expired, closure.Token),
            ExerciseAndCancelAsync(fixture, resolver, expired, closure)).ConfigureAwait(true);
        Assert.Equal(0, resolver.Statistics.ActiveRequests); Assert.Equal(0, resolver.Statistics.SourceRequests);
    }

    private static async Task ExerciseAndCancelAsync(TrustEpochLifetimeWireFixture fixture, DnssecTrustEpochResolver resolver,
        bool expired, CancellationTokenSource closure)
    {
        var question = new DnsQuestion(DnsName.Parse("www.example."), 1, 1);
        try
        {
            var original = await resolver.ResolveDnssecAsync(question, closure.Token).ConfigureAwait(true);
            var crypto = fixture.Verifier.Calls;
            var hit = await resolver.ResolveDnssecAsync(question, closure.Token).ConfigureAwait(true);
            if (expired)
            {
                Assert.Equal(DnssecResolutionOutcome.Failure, original.Outcome); Assert.Equal(DnssecResolutionOutcome.Failure, hit.Outcome);
                Assert.Empty(original.Answers); Assert.Empty(hit.Answers); Assert.Empty(hit.Authority); Assert.Null(hit.UnsignedDelegation);
                Assert.Equal(0u, original.AuthenticatedTtl); Assert.Equal(0u, hit.AuthenticatedTtl);
                Assert.Equal(0, resolver.Statistics.Entries); Assert.Equal(0, fixture.DataCalls);
            }
            else
            {
                Assert.Equal(DnssecResolutionOutcome.Authenticated, original.Outcome); Assert.Equal(DnssecResolutionOutcome.Authenticated, hit.Outcome);
                Assert.Equal(1u, original.AuthenticatedTtl); Assert.Equal(1u, Assert.Single(original.Answers).Ttl);
                Assert.Equal(3u, hit.AuthenticatedTtl); Assert.Equal(3u, Assert.Single(hit.Answers).Ttl);
                Assert.Equal(crypto, fixture.Verifier.Calls); Assert.Equal(1, fixture.BootstrapCalls); Assert.Equal(1, fixture.DataCalls);
                fixture.Clock.Advance(1);
                var aged = await resolver.ResolveDnssecAsync(question, closure.Token).ConfigureAwait(true);
                Assert.Equal(2u, aged.AuthenticatedTtl); Assert.Equal(2u, Assert.Single(aged.Answers).Ttl);
                Assert.Equal(crypto, fixture.Verifier.Calls); Assert.Equal(1, fixture.BootstrapCalls);
                fixture.Clock.Advance(2);
                var fresh = await resolver.ResolveDnssecAsync(question, closure.Token).ConfigureAwait(true);
                Assert.Equal(DnssecResolutionOutcome.Authenticated, fresh.Outcome); Assert.Equal(1u, fresh.AuthenticatedTtl);
                Assert.Equal(2, fixture.DataCalls);
            }
            Assert.Equal(2, fixture.BootstrapCalls); Assert.Equal(2, fixture.Verifier.Failures);
        }
        finally { await closure.CancelAsync().ConfigureAwait(true); }
    }

    private static async Task ServeAsync(TrustEpochLifetimeWireFixture fixture, UdpClient udp, TcpListener tcp,
        bool fallback, bool expired, CancellationToken token)
    {
        for (var index = 0; index < (expired ? 2 : 4); index++)
        {
            var packet = await udp.ReceiveAsync(token).ConfigureAwait(true);
            var query = DnsMessageCodec.DecodeQuery(packet.Buffer);
            var question = Assert.IsType<DnsQuestion>(query.Question);
            Assert.Equal(new DnsQuestion(question.Type == 48 ? fixture.Origin : DnsName.Parse("www.example."), question.Type, 1), question);
            Assert.Contains(question.Type, new ushort[] { 1, 48 });
            Assert.True(query.DnssecOk); Assert.Equal(16, query.Flags & 16);
            var records = fixture.Answer(question, expired ? 1u : 5u);
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
