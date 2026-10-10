using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ClientResponseProjectionTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task OwnedNativeEvidenceCanBePreparedWithBothDoPoliciesAndQueuedAging(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var clock = new ProjectionClock();
        var resolver = DnssecIterativeResolver.CreateWithClientProof(upstream, OnlineDnssecWireFixture.Verifier,
            zones.Anchor, [root.Server], child.Server.Port, time: clock);
        foreach (var name in new[] { "alias.example.", "missing.child.example." })
        {
            var question = new DnsQuestion(DnsName.Parse(name), 1, 1);
            var result = await resolver.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
            var sourceCalls = root.Requests.Count + child.Requests.Count;
            clock.Advance(1);
            foreach (var dnssecOk in new[] { false, true })
            {
                Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var snapshot));
                Assert.Equal(result.AuthenticatedTtl - 1, snapshot.RemainingTtl);
                Assert.Equal(dnssecOk, snapshot.Answers.Concat(snapshot.Authority).Any(record => record.Type == 46));
                Assert.All(snapshot.Answers.Concat(snapshot.Authority), record => Assert.Equal(snapshot.RemainingTtl, record.Ttl));
                Assert.DoesNotContain(snapshot.Answers.Concat(snapshot.Authority), record => record.Type is 2 or 43 or 48);
            }
            Assert.Equal(sourceCalls, root.Requests.Count + child.Requests.Count);
        }
    }
    private sealed class ProjectionClock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => ticks;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100).AddTicks(ticks);
        internal void Advance(int seconds) => ticks += TimeSpan.FromSeconds(seconds).Ticks;
    }
}
