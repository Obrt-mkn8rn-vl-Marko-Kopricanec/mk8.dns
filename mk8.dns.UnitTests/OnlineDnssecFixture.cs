using System.Collections.Concurrent;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class OnlineDnssecFixture : IDnssecUpstream, IDisposable
{
    private readonly DnssecChainFixture chain = new();
    internal OnlineDnssecFixture()
    {
        RootSoa = AuthorityFixture.Zone().Soa.WithTtl(300);
        ChildSoa = RootSoa.WithOwner(Child);
        RootRecords.Add(DnssecFixture.A("www.example."));
        ChildRecords.Add(DnssecFixture.A("www.child.example."));
    }

    internal DnsName Root => chain.Parent;
    internal DnsName Child => chain.Child;
    internal DnsRecord RootSoa { get; }
    internal DnsRecord ChildSoa { get; }
    internal DnssecChainFixture.ClockProvider Clock => chain.Clock;
    internal DnssecTrustAnchor Anchor(bool ds = false) => new(ds ? DnssecKeys.CreateDs(chain.ParentCskRecord, 0) : chain.ParentCskRecord);
    internal static DnsServerEndpoint RootServer { get; } = new([127, 0, 0, 1], 5300);
    internal static DnsServerEndpoint ChildServer { get; } = new([127, 0, 0, 2], 5400);
    internal ConcurrentQueue<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = new();
    internal List<DnsRecord> RootRecords { get; } = [];
    internal List<DnsRecord> ChildRecords { get; } = [];
    internal bool UnsignedChild { get; set; }
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? Transform { get; set; }
    internal Func<DnsQuestion, DnsServerEndpoint, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Override { get; set; }

    internal DnssecIterativeResolver Resolver(bool dsAnchor = false, int exchanges = 64, int aliases = 16,
        int attempts = 512, IDnssecSignatureVerifier? verifier = null)
        => new(this, verifier ?? DnssecFixture.Verifier, Anchor(dsAnchor), [RootServer], ChildServer.Port,
            exchanges, aliases, attempts, Clock);

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        Calls.Enqueue((question, server));
        cancellationToken.ThrowIfCancellationRequested();
        return Override is null ? ValueTask.FromResult(Transform?.Invoke(Default(question, server)) ?? Default(question, server))
            : Override(question, server, cancellationToken);
    }

    internal DnsUpstreamEvidence Default(DnsQuestion question, DnsServerEndpoint server)
    {
        if (question.Type == 48 && question.Name.Equals(server.Equals(RootServer) ? Root : Child))
            return Reply(question, server, [.. server.Equals(RootServer) ? chain.ParentRecords : chain.ChildRecords,
                server.Equals(RootServer) ? chain.ParentSignature : chain.ChildSignature]);
        if (server.Equals(RootServer) && question.Type == 43 && question.Name.Equals(Child))
            return UnsignedChild ? Unsigned(question, server) : Reply(question, server, [chain.Delegation, chain.DelegationSignature]);
        if (server.Equals(RootServer) && question.Name.IsSubdomainOf(Child) && question.Type != 43)
            return Referral(question, server);
        return Terminal(question, server);
    }

    internal DnsRecord Sign(IReadOnlyList<DnsRecord> records, bool child = false, DnssecSignatureWindow? window = null)
        => DnssecChainFixture.Sign(records, child ? chain.ChildZskRecord : chain.ParentZskRecord,
            child ? chain.ChildZsk : chain.ParentZsk, window);

    internal static DnsRecord Nsec(DnsName owner, DnsName next, params ushort[] types)
        => new(owner, 47, 300, [.. next.ToWire(), .. NsecBitmap.Encode(types.Concat([(ushort)46, (ushort)47]))]);

    internal DnsUpstreamEvidence Referral(DnsQuestion question, DnsServerEndpoint server, DnsName? cut = null, string? target = null)
    {
        var name = DnsName.Parse(target ?? "ns.child.example.");
        return Reply(question, server, [], [new DnsRecord(cut ?? Child, 2, 300, name.ToWire())],
            [new DnsRecord(name, 1, 300, ChildServer.GetAddress())], authoritative: false);
    }

    internal DnsUpstreamEvidence Unsigned(DnsQuestion question, DnsServerEndpoint server)
    {
        var nsec = Nsec(Child, DnsName.Parse("z.example."), 2);
        return Reply(question, server, [], [RootSoa, nsec, Sign([RootSoa]), Sign([nsec])]);
    }

    private DnsUpstreamEvidence Terminal(DnsQuestion question, DnsServerEndpoint server)
    {
        var child = server.Equals(ChildServer);
        var all = child ? ChildRecords : RootRecords;
        var records = all.Where(record => record.Owner.Equals(question.Name) && (record.Type == question.Type || record.Type == 5)).ToArray();
        if (records.Length != 0) return Reply(question, server, [.. records, Sign(records, child)]);
        var origin = child ? Child : Root;
        var soa = child ? ChildSoa : RootSoa;
        var existing = all.Any(record => record.Owner.Equals(question.Name));
        var owner = existing ? question.Name : origin;
        var next = existing ? origin : DnsName.Parse(child ? "www.child.example." : "www.example.");
        var nsec = Nsec(owner, next, existing ? [1] : [2, 6, 48]);
        return Reply(question, server, [], [soa, nsec, Sign([soa], child), Sign([nsec], child)], code: existing ? (ushort)0 : (ushort)3);
    }

    internal static DnsUpstreamEvidence Reply(DnsQuestion question, DnsServerEndpoint server, DnsRecord[] answers,
        DnsRecord[]? authority = null, DnsRecord[]? additional = null, bool authoritative = true, ushort code = 0)
        => new(question, server, 73, (ushort)((authoritative ? 0x8430 : 0x8030) | code), code,
            true, 1232, 0, 0x8000, answers, authority ?? [], additional ?? []);

    internal static DnsUpstreamEvidence Copy(DnsUpstreamEvidence reply, DnsRecord[]? answers = null, DnsRecord[]? authority = null,
        DnsRecord[]? additional = null, DnsQuestion? question = null, DnsServerEndpoint? server = null, ushort? flags = null,
        byte? version = null, ushort? ednsFlags = null)
        => new(question ?? reply.Question, server ?? reply.Server, reply.Id, flags ?? reply.Flags, reply.ResponseCode,
            reply.HasEdns, reply.UdpPayloadSize, version ?? reply.EdnsVersion, ednsFlags ?? reply.EdnsFlags,
            answers ?? reply.Answers.ToArray(), authority ?? reply.Authority.ToArray(), additional ?? reply.Additional.ToArray());

    public void Dispose() => chain.Dispose();
}
