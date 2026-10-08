using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class AuthorityBacktrackingFixture : IDnssecUpstream, IDisposable
{
    internal OnlineDnssecFixture Source { get; } = new();
    internal static DnsServerEndpoint AlternateRoot { get; } = new([127, 0, 0, 5], 5300);
    internal static DnsServerEndpoint BadChild { get; } = new([127, 0, 0, 4], 5400);
    internal static DnsQuestion Question { get; } = new(DnsName.Parse("www.child.example."), 1, 1);
    internal List<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = [];
    internal Func<DnsQuestion, CancellationToken, ValueTask<DnsUpstreamEvidence>>? BadReply { get; set; }
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? AlternateReply { get; set; }
    internal bool BadKeyReply { get; set; }

    internal DnssecIterativeResolver Resolver(int exchanges = 64, int aliases = 16, int attempts = 512,
        IDnssecSignatureVerifier? verifier = null)
        => new(this, verifier ?? DnssecFixture.Verifier, Source.Anchor(), [OnlineDnssecFixture.RootServer, AlternateRoot],
            5400, exchanges, aliases, attempts, Source.Clock);

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        Calls.Add((question, server)); cancellationToken.ThrowIfCancellationRequested();
        if (server.Equals(BadChild) && question.Type != 48)
            return BadReply?.Invoke(question, cancellationToken) ?? ValueTask.FromResult<DnsUpstreamEvidence>(null!);
        var canonical = server.Equals(AlternateRoot) ? OnlineDnssecFixture.RootServer
            : server.Equals(BadChild) ? OnlineDnssecFixture.ChildServer : server;
        var reply = OnlineDnssecFixture.Copy(Source.Default(question, canonical), server: server);
        if (BadKeyReply && server.Equals(BadChild) && question.Type == 48)
            reply = OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Where(record => record.Type != 46).ToArray());
        if (server.Equals(OnlineDnssecFixture.RootServer) && !reply.Authoritative)
            reply = OnlineDnssecFixture.Copy(reply, additional: reply.Additional.Select(record => new DnsRecord(record.Owner, record.Type, record.Ttl, BadChild.GetAddress())).ToArray());
        if (server.Equals(AlternateRoot)) reply = AlternateReply?.Invoke(reply) ?? reply;
        return ValueTask.FromResult(reply);
    }

    public void Dispose() => Source.Dispose();
}
