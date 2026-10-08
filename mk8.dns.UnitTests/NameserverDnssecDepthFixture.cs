using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.UnitTests;

internal sealed class NameserverDnssecDepthFixture : IDnssecUpstream, IDisposable
{
    private readonly Level root = new("example.", 1);
    private readonly List<Level> zones = [];
    internal NameserverDnssecDepthFixture(int dependencies)
    {
        zones.Add(new Level("child.example.", 2));
        for (var index = 1; index <= dependencies; index++) zones.Add(new Level("n" + index + ".example.", (byte)(index + 2)));
    }
    internal int Calls { get; private set; }
    internal DnssecIterativeResolver Resolver() => new(this, DnssecFixture.Verifier, new DnssecTrustAnchor(root.Key),
        [root.Server], 5400, maximumExchanges: 128, maximumVerificationAttempts: 1024, time: new FixedClock());
    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Calls++;
        if (server.Equals(root.Server))
        {
            if (question.Type == 48) return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [root.Key, root.Sign(root.Key)]));
            var index = zones.FindIndex(zone => question.Name.IsSubdomainOf(zone.Origin)); var selected = zones[index];
            if (question.Type == 43)
            {
                var ds = DnssecKeys.CreateDs(selected.Key, 300); return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [ds, root.Sign(ds)]));
            }
            var last = index + 1 == zones.Count;
            var target = (last ? selected.Origin : zones[index + 1].Origin).PrependLabel(last ? "auth"u8 : "ns"u8);
            return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [], [new DnsRecord(selected.Origin, 2, 300, target.ToWire())],
                last ? [new DnsRecord(target, 1, 300, selected.Server.GetAddress())] : [], authoritative: false));
        }
        var current = zones.FindIndex(zone => zone.Server.Equals(server)); var level = zones[current];
        if (question.Type == 48) return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [level.Key, level.Sign(level.Key)]));
        var record = new DnsRecord(question.Name, 1, 300, current == 0 ? [192, 0, 2, 43] : zones[current - 1].Server.GetAddress());
        return ValueTask.FromResult(OnlineDnssecFixture.Reply(question, server, [record, level.Sign(record)]));
    }
    public void Dispose() { root.Dispose(); foreach (var zone in zones) zone.Dispose(); }
    private sealed class Level : IDisposable
    {
        private readonly EcdsaP256DnssecSigningKey key = EcdsaP256DnssecSigningKey.Create();
        internal Level(string origin, byte address) { Origin = DnsName.Parse(origin); Server = new DnsServerEndpoint([127, 0, 0, address], 5400); Key = DnssecKeys.CreateDnskey(Origin, 300, key.GetPublicKey()); }
        internal DnsName Origin { get; }
        internal DnsServerEndpoint Server { get; }
        internal DnsRecord Key { get; }
        internal DnsRecord Sign(DnsRecord record) => DnssecRrsetSigner.Sign([record], Key, key, DnssecFixture.Verifier, DnssecFixture.Window);
        public void Dispose() => key.Dispose();
    }
    private sealed class FixedClock : TimeProvider { public override long GetTimestamp() => 0; public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100); }
}
