using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.UnitTests;

internal sealed class OnlineDnssecHierarchyFixture : IDnssecUpstream, IDisposable
{
    private readonly List<Level> levels = [];
    internal OnlineDnssecHierarchyFixture(int cuts)
    {
        var origin = DnsName.Parse("example.");
        for (var index = 0; index <= cuts; index++)
        {
            if (index != 0) origin = origin.PrependLabel(System.Text.Encoding.ASCII.GetBytes("n" + index));
            levels.Add(new Level(origin, new DnsServerEndpoint([127, 0, 0, (byte)(index + 1)], 5300)));
        }
        Question = new DnsQuestion(origin.PrependLabel("www"u8), 1, 1);
    }

    internal DnsQuestion Question { get; }
    internal int Calls { get; private set; }
    internal DnssecIterativeResolver Resolver() => new(this, DnssecFixture.Verifier, new DnssecTrustAnchor(levels[0].Dnskey),
        [levels[0].Server], 5300, time: new FixedClock());

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        var index = levels.FindIndex(level => level.Server.Equals(server));
        var current = levels[index];
        if (question.Type == 48)
            return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [current.Dnskey, current.Sign([current.Dnskey])]));
        if (question.Type == 43)
        {
            var ds = DnssecKeys.CreateDs(levels[index + 1].Dnskey, 300);
            return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [ds, current.Sign([ds])]));
        }
        if (index + 1 != levels.Count)
        {
            var next = levels[index + 1];
            var ns = next.Origin.PrependLabel("ns"u8);
            return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [],
                [new DnsRecord(next.Origin, 2, 300, ns.ToWire())], [new DnsRecord(ns, 1, 300, next.Server.GetAddress())], authoritative: false));
        }
        var data = DnssecFixture.A(question.Name.ToString());
        return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [data, current.Sign([data])]));
    }

    public void Dispose()
    {
        foreach (var level in levels) level.Dispose();
    }

    private sealed class Level : IDisposable
    {
        private readonly EcdsaP256DnssecSigningKey key = EcdsaP256DnssecSigningKey.Create();
        internal Level(DnsName origin, DnsServerEndpoint server)
        {
            Origin = origin;
            Server = server;
            Dnskey = DnssecKeys.CreateDnskey(origin, 300, key.GetPublicKey());
        }
        internal DnsName Origin { get; }
        internal DnsServerEndpoint Server { get; }
        internal DnsRecord Dnskey { get; }
        internal DnsRecord Sign(DnsRecord[] records) => DnssecRrsetSigner.Sign(records, Dnskey, key, DnssecFixture.Verifier, DnssecFixture.Window);
        public void Dispose() => key.Dispose();
    }
    private sealed class FixedClock : TimeProvider
    {
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
