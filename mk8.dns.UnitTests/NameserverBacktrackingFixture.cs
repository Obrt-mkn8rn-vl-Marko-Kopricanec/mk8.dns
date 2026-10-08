using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class NameserverBacktrackingFixture : IDnssecUpstream, IDisposable
{
    internal NameserverDnssecFixture Source { get; } = new();
    internal static DnsServerEndpoint AlternateRoot => AuthorityBacktrackingFixture.AlternateRoot;
    internal static DnsServerEndpoint AlternateProvider { get; } = new([127, 0, 0, 6], 5400);
    internal static DnsServerEndpoint ReplacementChild { get; } = new([127, 0, 0, 7], 5400);
    internal List<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = [];
    internal bool QueryFailsAfterAddress { get; set; }
    internal Action? AfterFailure { get; set; }
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? AlternateReply { get; set; }
    internal DnssecIterativeResolver Resolver(int exchanges = 64, int attempts = 512)
        => new(this, DnssecFixture.Verifier, GetAnchor(), [NameserverDnssecFixture.RootServer, AlternateRoot],
            5400, exchanges, maximumVerificationAttempts: attempts, time: Source.Clock);
    private Mk8.Dns.Engine.Dnssec.DnssecTrustAnchor GetAnchor()
        => new(Source.Default(new DnsQuestion(DnsName.Parse("example."), 48, 1), NameserverDnssecFixture.RootServer).Answers[0]);

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        Calls.Add((question, server)); cancellationToken.ThrowIfCancellationRequested();
        if (!QueryFailsAfterAddress && server.Equals(NameserverDnssecFixture.ProviderServer) && question.Type is 1 or 28
            || QueryFailsAfterAddress && server.Equals(Source.ChildServer) && question.Type != 48)
        {
            AfterFailure?.Invoke(); return ValueTask.FromResult<DnsUpstreamEvidence>(null!);
        }
        var canonical = server.Equals(AlternateRoot) ? NameserverDnssecFixture.RootServer
            : server.Equals(AlternateProvider) ? NameserverDnssecFixture.ProviderServer
            : server.Equals(ReplacementChild) ? Source.ChildServer : server;
        var reply = OnlineDnssecFixture.Copy(Source.Default(question, canonical), server: server);
        if (server.Equals(AlternateRoot) && !reply.Authoritative)
        {
            var providerCut = DnsName.Parse("provider.example.");
            if (question.Name.IsSubdomainOf(providerCut))
                reply = OnlineDnssecFixture.Copy(reply, additional: reply.Additional.Select(record =>
                    new DnsRecord(record.Owner, record.Type, record.Ttl, AlternateProvider.GetAddress())).ToArray());
            else if (QueryFailsAfterAddress)
            {
                var ns = DnsName.Parse("ns.child.example.");
                reply = OnlineDnssecFixture.Copy(reply, authority: [new DnsRecord(DnsName.Parse("child.example."), 2, 300, ns.ToWire())],
                    additional: [new DnsRecord(ns, 1, 300, ReplacementChild.GetAddress())]);
            }
        }
        if (server.Equals(AlternateRoot)) reply = AlternateReply?.Invoke(reply) ?? reply;
        return ValueTask.FromResult(reply);
    }
    public void Dispose() => Source.Dispose();
}
