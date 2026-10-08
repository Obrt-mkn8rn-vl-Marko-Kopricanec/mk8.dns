using System.Collections.Concurrent;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure.Cryptography;

namespace Mk8.Dns.UnitTests;

internal sealed class RootPrimingFixture : IDnssecUpstream, IDisposable
{
    private readonly EcdsaP256DnssecSigningKey key = EcdsaP256DnssecSigningKey.Create();
    internal RootPrimingFixture(int names = 2)
    {
        Dnskey = DnssecKeys.CreateDnskey(Root, 300, key.GetPublicKey());
        for (var index = 0; index < names; index++)
        {
            var name = DnsName.Parse("ns" + index + ".fixture.");
            NameServers.Add(new DnsRecord(Root, 2, 300, name.ToWire()));
            Addresses.Add(new DnsRecord(name, 1, 300, [192, 0, 2, (byte)(index + 1)]));
            Addresses.Add(new DnsRecord(name, 28, 300, [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)(index + 1)]));
        }
    }

    internal static DnsName Root { get; } = DnsName.Parse(".");
    internal static DnsServerEndpoint Server { get; } = new([127, 0, 0, 1], 5300);
    internal DnsRecord Dnskey { get; set; }
    internal List<DnsRecord> NameServers { get; } = [];
    internal List<DnsRecord> Addresses { get; } = [];
    internal DnsRecord[]? Additional { get; set; }
    internal DnssecChainFixture.ClockProvider Clock { get; } = new();
    internal ConcurrentQueue<(DnsQuestion Question, DnsServerEndpoint Server)> Calls { get; } = new();
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? Transform { get; set; }
    internal Func<DnsQuestion, DnsServerEndpoint, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Override { get; set; }

    internal DnssecRootPrimer Primer(bool ds = false, int exchanges = 128, int attempts = 512,
        DnsServerEndpoint[]? bootstrap = null, IDnssecSignatureVerifier? verifier = null)
        => new(this, verifier ?? DnssecFixture.Verifier, new(ds ? DnssecKeys.CreateDs(Dnskey, 0) : Dnskey),
            bootstrap ?? [Server], 5300, exchanges, attempts, Clock);

    public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken token)
    {
        Calls.Enqueue((question, server)); token.ThrowIfCancellationRequested();
        return Override is null ? ValueTask.FromResult(Transform?.Invoke(Default(question, server)) ?? Default(question, server))
            : Override(question, server, token);
    }

    internal DnsUpstreamEvidence Default(DnsQuestion question, DnsServerEndpoint server)
    {
        if (question.Type == 48) return OnlineDnssecFixture.Reply(question, server, [Dnskey, Sign([Dnskey])]);
        if (question.Type == 2) return OnlineDnssecFixture.Reply(question, server,
            NameServers.Count == 0 ? [] : [.. NameServers, Sign(NameServers)], additional: Additional ?? Addresses.ToArray());
        return OnlineDnssecFixture.Reply(question, server, Addresses.Where(record => record.Owner.Equals(question.Name) && record.Type == question.Type).ToArray());
    }

    internal DnsRecord Sign(IReadOnlyList<DnsRecord> records, DnssecSignatureWindow? window = null)
        => DnssecRrsetSigner.Sign(records, Dnskey, key, DnssecFixture.Verifier, window ?? DnssecFixture.Window);
    public void Dispose() => key.Dispose();
}
