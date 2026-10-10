using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ClientProofCacheTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task NativeCachedAliasAndDenialEncodeWithoutInfrastructureOrNewAcquisition(bool ipv6, bool tcp)
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
        var resolver = DnssecIterativeResolver.CreateWithClientProof(upstream, OnlineDnssecWireFixture.Verifier,
            zones.Anchor, [root.Server], child.Server.Port, time: clock);
        var cache = CachingDnssecResolver.CreateWithClientProofCache(resolver);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        foreach (var name in new[] { "alias.example.", "missing.child.example." })
        {
            var question = new DnsQuestion(DnsName.Parse(name), 1, 1);
            await cache.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
            var calls = root.Requests.Count + child.Requests.Count;
            clock.Advance(1);
            var result = await cache.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
            foreach (var dnssecOk in new[] { false, true })
            {
                var request = UpstreamMessageCodec.EncodeDnssecQuery(19, question);
                BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0100);
                if (!dnssecOk) request[^4] = 0;
                var query = DnsMessageCodec.DecodeQuery(request);
                Assert.True(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true,
                    authenticatedDataAllowed: true, out var message));
                var decoded = UpstreamMessageCodec.DecodeDnssecResponse(message, 19, question, root.Server);
                Assert.False(decoded.Truncated);
                Assert.Equal(dnssecOk, (decoded.Evidence.Flags & 0x0020) != 0);
                Assert.Equal(result.ResponseCode, decoded.Evidence.ResponseCode);
                Assert.All(decoded.Evidence.Answers.Concat(decoded.Evidence.Authority), record => Assert.Equal(result.AuthenticatedTtl, record.Ttl));
                Assert.DoesNotContain(decoded.Evidence.Answers.Concat(decoded.Evidence.Authority), record => record.Type is 2 or 43 or 48);
                Assert.Empty(decoded.Evidence.Additional);
            }
            Assert.Equal(calls, root.Requests.Count + child.Requests.Count);
        }
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
