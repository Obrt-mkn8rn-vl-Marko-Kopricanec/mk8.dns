using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.UnitTests;

internal sealed class OperationCutDependencyFixture : IDnssecUpstream, IDisposable
{
    private readonly Level root = new("example.");
    private readonly Level provider = new("provider.example.");
    private readonly Level child = new("child.example.");
    internal static DnsServerEndpoint Root { get; } = new([127, 0, 0, 1], 5300);
    internal static DnsServerEndpoint Provider { get; } = new([127, 0, 0, 3], 5400);
    internal static DnsServerEndpoint Child { get; } = new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 5400);
    internal static DnsName Target { get; } = DnsName.Parse("ns.provider.example.");
    internal static DnsQuestion Question { get; } = new(DnsName.Parse("www.child.example."), 1, 1);
    internal DnssecChainFixture.ClockProvider Clock { get; } = new();
    internal List<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = [];
    internal bool FailProviderKeys { get; set; }
    internal bool UnsignedProvider { get; set; }
    internal bool ParentAddress { get; set; } = true;
    internal bool CorruptProviderDs { get; set; }
    internal DnssecSignatureWindow? FirstProviderDsWindow { get; set; }
    internal Action? AfterAddressFailure { get; set; }
    internal bool SignedOnAaaa { get; set; }
    private int providerDsCalls;
    private bool aaaa;
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? Transform { get; set; }
    internal DnssecIterativeResolver Resolver(int attempts = 512)
        => new(this, DnssecFixture.Verifier, new DnssecTrustAnchor(root.Key), [Root], 5400,
            maximumVerificationAttempts: attempts, time: Clock);

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Calls.Add((question, server));
        if (server.Equals(Root) && question.Name.Equals(Target) && question.Type == 28) aaaa = true;
        var level = server.Equals(Root) ? root : server.Equals(Provider) ? provider : child;
        DnsUpstreamEvidence reply;
        if (question.Type == 48)
            reply = OnlineDnssecFixture.Reply(question, server,
                FailProviderKeys && server.Equals(Provider) ? [level.Key] : [level.Key, level.Sign([level.Key])]);
        else if (server.Equals(Root) && question.Type == 43)
        {
            var selected = question.Name.Equals(provider.Origin) ? provider : child;
            if (UnsignedProvider && selected == provider && !(SignedOnAaaa && aaaa))
            {
                var soa = AuthorityFixture.Zone().Soa;
                var nsec = OnlineDnssecFixture.Nsec(provider.Origin, DnsName.Parse("z.example."), 2);
                reply = OnlineDnssecFixture.Reply(question, server, [], [soa, nsec, root.Sign([soa]), root.Sign([nsec])]);
            }
            else
            {
                var ds = DnssecKeys.CreateDs(selected.Key, 300);
                var window = selected == provider && ++providerDsCalls == 1 ? FirstProviderDsWindow : null;
                var signature = root.Sign([ds], window);
                if (CorruptProviderDs && selected == provider)
                {
                    var data = signature.GetData(); data[^1] ^= 1;
                    signature = new DnsRecord(signature.Owner, signature.Type, signature.Ttl, data);
                }
                reply = OnlineDnssecFixture.Reply(question, server, [ds, signature]);
            }
        }
        else if (server.Equals(Root) && question.Name.Equals(Target) && question.Type == 28 && ParentAddress)
        {
            var address = new DnsRecord(Target, 28, 300, Child.GetAddress());
            reply = OnlineDnssecFixture.Reply(question, server, [address, root.Sign([address])]);
        }
        else if (server.Equals(Root))
        {
            var selected = question.Name.IsSubdomainOf(provider.Origin) ? provider : child;
            var ns = selected == provider ? DnsName.Parse("auth.provider.example.") : Target;
            reply = OnlineDnssecFixture.Reply(question, server, [], [new DnsRecord(selected.Origin, 2, 300, ns.ToWire())],
                selected == provider ? [new DnsRecord(ns, 1, 300, Provider.GetAddress())] : [], authoritative: false);
        }
        else if (server.Equals(Provider))
        {
            if (question.Type == 1)
            {
                AfterAddressFailure?.Invoke(); reply = OnlineDnssecFixture.Reply(question, server, [], code: 2);
            }
            else
            {
                var address = new DnsRecord(Target, 28, 7, Child.GetAddress());
                reply = OnlineDnssecFixture.Reply(question, server, [address, provider.Sign([address])]);
            }
        }
        else
        {
            var address = DnssecFixture.A(question.Name.ToString());
            reply = OnlineDnssecFixture.Reply(question, server, [address, child.Sign([address])]);
        }
        return ValueTask.FromResult(Transform?.Invoke(reply) ?? reply);
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
