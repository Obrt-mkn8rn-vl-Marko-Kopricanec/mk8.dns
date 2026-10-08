using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class OperationCutFixture : IDnssecUpstream, IDisposable
{
    internal OnlineDnssecFixture Source { get; } = new();
    internal static DnsName Alias { get; } = DnsName.Parse("start.child.example.");
    internal static DnsName Target { get; } = DnsName.Parse("target.child.example.");
    internal static DnsQuestion Question { get; } = new(Alias, 1, 1);
    internal List<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = [];
    internal int ParentTarget { get; set; }
    internal bool ChildTarget { get; set; }
    internal bool Dname { get; set; }
    internal DnsQuestion Query => Dname ? new DnsQuestion(DnsName.Parse("target.branch.child.example."), 1, 1) : Question;
    internal Func<CancellationToken, ValueTask<DnsUpstreamEvidence>>? TargetReply { get; set; }
    internal Action? AfterAlias { get; set; }
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? Transform { get; set; }
    internal DnssecIterativeResolver Resolver(int exchanges = 64, int attempts = 512)
        => new(this, DnssecFixture.Verifier, Source.Anchor(), [OnlineDnssecFixture.RootServer],
            OnlineDnssecFixture.ChildServer.Port, exchanges, maximumVerificationAttempts: attempts, time: Source.Clock);

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Calls.Add((question, server));
        if (server.Equals(OnlineDnssecFixture.RootServer) && question.Name.Equals(Target) && TargetReply is not null) return TargetReply(cancellationToken);
        DnsUpstreamEvidence reply;
        if (server.Equals(OnlineDnssecFixture.ChildServer) && question.Name.Equals(Query.Name) && question.Type != 48)
        {
            var alias = new DnsRecord(Dname ? DnsName.Parse("branch.child.example.") : Alias, Dname ? (ushort)39 : (ushort)5, 300,
                Dname ? Source.Child.ToWire() : Target.ToWire());
            if (Dname) reply = OnlineDnssecFixture.Reply(question, server, [alias, Source.Sign([alias], child: true),
                new DnsRecord(Query.Name, 5, 300, Target.ToWire())]);
            else reply = OnlineDnssecFixture.Reply(question, server, [alias, Source.Sign([alias], child: true)]);
            AfterAlias?.Invoke();
        }
        else if (server.Equals(OnlineDnssecFixture.RootServer) && question.Name.Equals(Target) && question.Type is not (43 or 48))
        {
            if (ParentTarget == 0) reply = Source.Referral(question, server);
            else if (ParentTarget == 1)
            {
                var record = DnssecFixture.A(Target.ToString()); reply = OnlineDnssecFixture.Reply(question, server, [record, Source.Sign([record])]);
            }
            else if (ParentTarget == 2)
            {
                var nsec = OnlineDnssecFixture.Nsec(Source.Root, DnsName.Parse("www.example."), 2, 6, 48);
                reply = OnlineDnssecFixture.Reply(question, server, [], [Source.RootSoa, nsec, Source.Sign([Source.RootSoa]), Source.Sign([nsec])], code: 3);
            }
            else
            {
                var record = new DnsRecord(Target, 5, 300, DnsName.Parse("www.example.").ToWire());
                reply = OnlineDnssecFixture.Reply(question, server, [record, Source.Sign([record])]);
            }
        }
        else if (server.Equals(OnlineDnssecFixture.ChildServer) && question.Name.Equals(Target) && ChildTarget)
        {
            var record = DnssecFixture.A(Target.ToString()); reply = OnlineDnssecFixture.Reply(question, server, [record, Source.Sign([record], child: true)]);
        }
        else if (server.Equals(OnlineDnssecFixture.RootServer) && question.Name.Equals(Query.Name) && question.Type != 48)
            reply = Source.Referral(question, server);
        else reply = Source.Default(question, server);
        return ValueTask.FromResult(Transform?.Invoke(reply) ?? reply);
    }
    public void Dispose() => Source.Dispose();
}
