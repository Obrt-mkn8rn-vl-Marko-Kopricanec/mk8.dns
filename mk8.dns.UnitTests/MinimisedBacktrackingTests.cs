using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class MinimisedBacktrackingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExpiredDiscoveryFromDeadChildDoesNotPoisonSelectedAlternate(bool expireAbandoned)
    {
        using var fixture = new Branches(expireAbandoned);
        var resolver = DnssecIterativeResolver.CreateWithQnameMinimisation(fixture, DnssecFixture.Verifier,
            fixture.Source.Anchor(), [OnlineDnssecFixture.RootServer, AuthorityBacktrackingFixture.AlternateRoot],
            new DnsQnameMinimisationPolicy(32), OnlineDnssecFixture.ChildServer.Port, time: fixture.Source.Clock);
        var result = await resolver.ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.True(fixture.AbandonedDiscovery);
        Assert.True(fixture.SelectedDiscovery);
        Assert.Equal(1, fixture.FailedAnswers);
        Assert.InRange(result.AuthenticatedTtl, 4u, 300u);
        Assert.Equal(Assert.Single(fixture.Source.ChildRecords).GetData(), Assert.Single(result.Answers).GetData());
        Assert.Empty(result.Authority);
    }

    private sealed class Branches(bool expire) : IDnssecUpstream, IDisposable
    {
        internal OnlineDnssecFixture Source { get; } = new();
        internal bool AbandonedDiscovery { get; private set; }
        internal bool SelectedDiscovery { get; private set; }
        internal int FailedAnswers { get; private set; }
        private static DnsServerEndpoint Dead { get; } = new([127, 0, 0, 4], 5400);
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var bad = server.Equals(Dead);
            if (bad && question.Type == 1)
            {
                FailedAnswers++;
                if (expire) Source.Clock.Advance(4);
                return ValueTask.FromResult<DnsUpstreamEvidence>(null!);
            }
            var canonical = bad ? OnlineDnssecFixture.ChildServer
                : server.Equals(AuthorityBacktrackingFixture.AlternateRoot) ? OnlineDnssecFixture.RootServer : server;
            var reply = Source.Default(question, canonical);
            if (canonical.Equals(OnlineDnssecFixture.ChildServer) && question.Type == 2)
            {
                if (bad) AbandonedDiscovery = true;
                else SelectedDiscovery = true;
                var nsec = OnlineDnssecFixture.Nsec(question.Name, Source.Child, 1);
                var window = bad ? new DnssecSignatureWindow(99, 103) : new DnssecSignatureWindow(99, 1000);
                reply = OnlineDnssecFixture.Reply(question, canonical, [],
                    [Source.ChildSoa, nsec, Source.Sign([Source.ChildSoa], child: true, window), Source.Sign([nsec], child: true, window)]);
            }
            if (server.Equals(OnlineDnssecFixture.RootServer) && !reply.Authoritative)
            {
                reply = OnlineDnssecFixture.Copy(reply, additional: [.. reply.Additional.Select(record =>
                    new DnsRecord(record.Owner, record.Type, record.Ttl, Dead.GetAddress()))]);
            }

            return ValueTask.FromResult(OnlineDnssecFixture.Copy(reply, server: server));
        }
        public void Dispose() => Source.Dispose();
    }
}
