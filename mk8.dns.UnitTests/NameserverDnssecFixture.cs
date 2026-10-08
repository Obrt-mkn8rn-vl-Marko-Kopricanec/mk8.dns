using System.Collections.Concurrent;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.UnitTests;

internal sealed class NameserverDnssecFixture : IDnssecUpstream, IDisposable
{
    private readonly Level root = new("example.");
    private readonly Level provider = new("provider.example.");
    private readonly Level child = new("child.example.");
    internal static DnsServerEndpoint RootServer { get; } = new([127, 0, 0, 1], 5300);
    internal static DnsServerEndpoint ProviderServer { get; } = new([127, 0, 0, 3], 5400);
    internal DnsServerEndpoint ChildServer => new(Address, 5400);
    internal DnsName Target { get; set; } = DnsName.Parse("ns.provider.example.");
    internal byte[] Address { get; set; } = [127, 0, 0, 2];
    internal uint AddressTtl { get; set; } = 300;
    internal DnssecSignatureWindow AddressWindow { get; set; } = DnssecFixture.Window;
    internal bool UnsignedProvider { get; set; }
    internal bool CyclicProvider { get; set; }
    internal DnssecChainFixture.ClockProvider Clock { get; } = new();
    internal ConcurrentQueue<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = new();
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? Transform { get; set; }
    internal Func<DnsQuestion, DnsServerEndpoint, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Override { get; set; }
    internal static DnsQuestion Question { get; } = new(DnsName.Parse("www.child.example."), 1, 1);

    internal DnssecIterativeResolver Resolver(int exchanges = 64, int attempts = 512, IDnssecSignatureVerifier? verifier = null)
        => new(this, verifier ?? DnssecFixture.Verifier, new DnssecTrustAnchor(root.Key), [RootServer], 5400, exchanges,
            maximumVerificationAttempts: attempts, time: Clock);

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        Calls.Enqueue((question, server)); cancellationToken.ThrowIfCancellationRequested();
        return Override is null ? ValueTask.FromResult(Transform?.Invoke(Default(question, server)) ?? Default(question, server))
            : Override(question, server, cancellationToken);
    }

    internal DnsUpstreamEvidence Default(DnsQuestion question, DnsServerEndpoint server)
    {
        var level = server.Equals(RootServer) ? root : server.Equals(ProviderServer) ? provider : child;
        if (question.Type == 48) return OnlineDnssecFixture.Reply(question, server, [level.Key, level.Sign([level.Key])]);
        if (server.Equals(RootServer) && question.Type == 43)
        {
            var selected = question.Name.Equals(provider.Origin) ? provider : child;
            if (UnsignedProvider && selected == provider)
            {
                var nsec = OnlineDnssecFixture.Nsec(provider.Origin, DnsName.Parse("z.example."), 2);
                var soa = AuthorityFixture.Zone().Soa;
                return OnlineDnssecFixture.Reply(question, server, [], [soa, nsec, root.Sign([soa]), root.Sign([nsec])]);
            }
            var ds = DnssecKeys.CreateDs(selected.Key, 300);
            return OnlineDnssecFixture.Reply(question, server, [ds, root.Sign([ds])]);
        }
        if (server.Equals(RootServer) && question.Name.IsSubdomainOf(child.Origin))
            return OnlineDnssecFixture.Reply(question, server, [], [new DnsRecord(child.Origin, 2, 300, Target.ToWire())],
                [new DnsRecord(Target, 1, 300, [127, 0, 0, 99])], authoritative: false);
        if (server.Equals(RootServer) && question.Name.IsSubdomainOf(provider.Origin))
        {
            var ns = DnsName.Parse(CyclicProvider ? "ns.child.example." : "auth.provider.example.");
            return OnlineDnssecFixture.Reply(question, server, [], [new DnsRecord(provider.Origin, 2, 300, ns.ToWire())],
                CyclicProvider ? [] : [new DnsRecord(ns, 1, 300, ProviderServer.GetAddress())], authoritative: false);
        }
        if (question.Name.Equals(Target))
        {
            var type = Address.Length == 4 ? (ushort)1 : (ushort)28;
            if (question.Type == type)
            {
                var address = new DnsRecord(Target, type, AddressTtl, Address);
                return OnlineDnssecFixture.Reply(question, server, [address, level.Sign([address], AddressWindow)]);
            }
            var soa = AuthorityFixture.Zone().Soa.WithOwner(level.Origin);
            var nsec = OnlineDnssecFixture.Nsec(Target, level.Origin, type);
            return OnlineDnssecFixture.Reply(question, server, [], [soa, nsec, level.Sign([soa]), level.Sign([nsec])]);
        }
        var record = DnssecFixture.A(question.Name.ToString());
        return OnlineDnssecFixture.Reply(question, server, [record, level.Sign([record])]);
    }

    internal DnsUpstreamEvidence AliasReply(DnsQuestion question, DnsServerEndpoint server, bool dname)
    {
        var owner = dname ? provider.Origin : Target;
        var record = new DnsRecord(owner, dname ? (ushort)39 : (ushort)5, 300, DnsName.Parse("alternate.example.").ToWire());
        return OnlineDnssecFixture.Reply(question, server, [record, provider.Sign([record])]);
    }

    public void Dispose() { root.Dispose(); provider.Dispose(); child.Dispose(); }

    private sealed class Level : IDisposable
    {
        private readonly EcdsaP256DnssecSigningKey key = EcdsaP256DnssecSigningKey.Create();
        internal Level(string origin) { Origin = DnsName.Parse(origin); Key = DnssecKeys.CreateDnskey(Origin, 300, key.GetPublicKey()); }
        internal DnsName Origin { get; }
        internal DnsRecord Key { get; }
        internal DnsRecord Sign(DnsRecord[] records, DnssecSignatureWindow? window = null)
            => DnssecRrsetSigner.Sign(records, Key, key, DnssecFixture.Verifier, window ?? DnssecFixture.Window);
        public void Dispose() => key.Dispose();
    }
}
