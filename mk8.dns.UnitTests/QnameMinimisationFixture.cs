using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class QnameMinimisationFixture : IDnssecUpstream, IDisposable
{
    internal OnlineDnssecFixture Source { get; } = new();
    internal List<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = [];
    internal Func<DnsQuestion, DnsServerEndpoint, DnsUpstreamEvidence, DnsUpstreamEvidence>? Transform { get; set; }
    internal Func<DnsQuestion, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Delayed { get; set; }
    internal static DnsServerEndpoint Alternate { get; } = new([127, 0, 0, 5], 5300);
    internal bool AlternateRoot { get; set; }
    internal DnssecIterativeResolver Resolver(int steps = 32, int exchanges = 64, int attempts = 512)
        => DnssecIterativeResolver.CreateWithQnameMinimisation(this, DnssecFixture.Verifier, Source.Anchor(),
            AlternateRoot ? [OnlineDnssecFixture.RootServer, Alternate] : [OnlineDnssecFixture.RootServer],
            new DnsQnameMinimisationPolicy(steps), OnlineDnssecFixture.ChildServer.Port, exchanges, 16, attempts, Source.Clock);

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        Calls.Add((question, server)); cancellationToken.ThrowIfCancellationRequested();
        if (Delayed is not null && question.Type == 2) return Delayed(question, cancellationToken);
        var canonical = server.Equals(Alternate) ? OnlineDnssecFixture.RootServer : server;
        var reply = Source.Default(question, canonical);
        if (question.Type == 2 && reply.Authoritative)
        {
            var child = canonical.Equals(OnlineDnssecFixture.ChildServer);
            var soa = child ? Source.ChildSoa : Source.RootSoa;
            var origin = child ? Source.Child : Source.Root;
            var nsec = OnlineDnssecFixture.Nsec(question.Name, origin, 1);
            reply = OnlineDnssecFixture.Reply(question, canonical, [], [soa, nsec, Source.Sign([soa], child), Source.Sign([nsec], child)]);
        }
        reply = OnlineDnssecFixture.Copy(reply, server: server);
        return ValueTask.FromResult(Transform?.Invoke(question, server, reply) ?? reply);
    }

    internal void AddAddress(string name, bool child = false, ushort type = 1)
        => (child ? Source.ChildRecords : Source.RootRecords).Add(new DnsRecord(DnsName.Parse(name), type, 300,
            type == 1 ? [192, 0, 2, 43] : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    internal void AddAlias(string owner, string target, bool child = true)
        => (child ? Source.ChildRecords : Source.RootRecords).Add(new DnsRecord(DnsName.Parse(owner), 5, 300, DnsName.Parse(target).ToWire()));
    public void Dispose() => Source.Dispose();
}
