using System.Collections.Concurrent;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class OnlineNsec3Fixture : IDisposable
{
    private readonly OnlineDnssecFixture upstream = new();
    internal OnlineNsec3Fixture() => upstream.Transform = Compose;
    internal bool Wildcard { get; set; }
    internal bool Unsigned { get => upstream.UnsignedChild; set => upstream.UnsignedChild = value; }
    internal bool OptOut { get; set; }
    internal byte[] Salt { get; set; } = [];
    internal Func<DnsUpstreamEvidence, DnsUpstreamEvidence>? Transform { get; set; }
    internal DnssecChainFixture.ClockProvider Clock => upstream.Clock;
    internal ConcurrentQueue<(DnsQuestion Question, DnsServerEndpoint Server)> Calls => upstream.Calls;
    internal DnssecIterativeResolver Resolver(int attempts = 512, int exchanges = 64, IDnssecSignatureVerifier? verifier = null)
        => upstream.Resolver(attempts: attempts, exchanges: exchanges, verifier: verifier);
    internal List<DnsRecord> RootRecords => upstream.RootRecords;
    internal DnsRecord Sign(DnsRecord record, bool child = false, DnssecSignatureWindow? window = null)
        => upstream.Sign([record], child, window);

    internal DnsRecord[] Ring(bool child = false)
    {
        var origin = child ? "child.example." : "example.";
        var entries = new Dictionary<string, ushort[]>(StringComparer.Ordinal)
        {
            [origin] = [2, 6, 46, 48],
            ["www." + origin] = [1, 46],
            ["empty." + origin] = [],
            ["leaf.empty." + origin] = [1, 46],
            ["branch." + origin] = [39, 46],
        };
        if (!child && !(Unsigned && OptOut)) entries["child.example."] = Unsigned ? [2] : [2, 43, 46];
        if (Wildcard) entries["*." + origin] = [1, 46];
        var sorted = entries.Select(item => (Hash: Nsec3ValidationFixture.Hash(item.Key, Salt), Types: item.Value))
            .OrderBy(item => Convert.ToHexString(item.Hash), StringComparer.Ordinal).ToArray();
        return sorted.Select((item, index) => Nsec3ValidationFixture.Record(item.Hash, sorted[(index + 1) % sorted.Length].Hash,
            item.Types, OptOut, Salt).WithOwner(DnsName.Parse(Nsec3ValidationFixture.Base32(item.Hash) + "." + origin))).ToArray();
    }

    private DnsUpstreamEvidence Compose(DnsUpstreamEvidence original)
    {
        var reply = original;
        var question = reply.Question;
        var child = reply.Server.Equals(OnlineDnssecFixture.ChildServer);
        if (question.Type != 48 && reply.Authoritative && (reply.Answers.Count == 0 || Wildcard && question.Name.ToString().StartsWith("new.", StringComparison.Ordinal)))
        {
            var ring = Ring(child);
            var soa = child ? upstream.ChildSoa : upstream.RootSoa;
            var sigs = ring.Select(record => Sign(record, child)).ToArray();
            var origin = child ? upstream.Child : upstream.Root;
            var exact = question.Name.Equals(origin) || question.Name.ToString().StartsWith("www.", StringComparison.Ordinal)
                || question.Name.ToString().StartsWith("empty.", StringComparison.Ordinal);
            var code = exact || question.Type == 43 || Wildcard ? (ushort)0 : (ushort)3;
            if (Wildcard && question.Type == 1 && question.Name.ToString().StartsWith("new.", StringComparison.Ordinal))
            {
                var data = DnssecFixture.A("*." + origin);
                reply = OnlineDnssecFixture.Reply(question, reply.Server,
                    [data.WithOwner(question.Name), Sign(data, child).WithOwner(question.Name)], [.. ring, .. sigs]);
            }
            else reply = OnlineDnssecFixture.Reply(question, reply.Server, [], [soa, Sign(soa, child), .. ring, .. sigs], code: code);
        }
        return Transform?.Invoke(reply) ?? reply;
    }
    public void Dispose() => upstream.Dispose();
}
