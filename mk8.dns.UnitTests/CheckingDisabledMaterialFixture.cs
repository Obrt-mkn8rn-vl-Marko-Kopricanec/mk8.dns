using System.Collections.Concurrent;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class CheckingDisabledMaterialFixture : IAsyncDisposable
{
    internal CheckingDisabledMaterialFixture(int exchanges = 64, int requests = 64, bool complete = true)
    {
        Upstream = new Source(this);
        Resolver = NonValidatingIterativeResolver.CreateWithDnssecMaterial(Upstream, [AnchorRefreshFixture.Server],
            maximumExchanges: exchanges, time: Epoch.Anchors.Keys.Clock);
        Processor = DnssecClientRequestProcessor.CreateWithCheckingDisabledSource(Epoch.Resolver, Resolver,
            new DnssecClientAccessPolicy([new DnssecClientNetwork([192, 0, 2, 0], 24)], authenticatedDataAllowed: true),
            Epoch.Anchors.Keys.Clock, complete, requests);
    }
    internal ClientProofEpochFixture Epoch { get; } = new();
    internal Source Upstream { get; }
    internal NonValidatingIterativeResolver Resolver { get; }
    internal DnssecClientRequestProcessor Processor { get; }
    internal Func<DnsQuestion, DnsServerEndpoint, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Override { get; set; }

    internal static DnsUpstreamEvidence Reply(DnsQuestion question, DnsServerEndpoint server, IEnumerable<DnsRecord> answers,
        IEnumerable<DnsRecord>? authority = null, IEnumerable<DnsRecord>? additional = null, byte code = 0)
        => new(question, server, 1, (ushort)(0x8430 | code), code, hasEdns: true, 1232, 0, 0x8000, answers, authority ?? [], additional ?? []);

    internal DnsRecord Signature(DnsRecord record)
    {
        var original = Epoch.Default(Epoch.Question, AnchorRefreshFixture.Server).Answers.Single(value => value.Type == 46).GetData();
        // Deliberately unsupported algorithm, expired window and invalid signature: CD bytes carry no validation claim.
        original[0] = (byte)(record.Type >> 8); original[1] = (byte)record.Type; original[2] = 253; original[3] = (byte)record.Owner.LabelCount;
        original.AsSpan(8, 8).Clear(); original[^1] ^= 1;
        return new DnsRecord(record.Owner, 46, record.Ttl, original);
    }
    internal static byte[] Request(ushort type = 1, bool dnssecOk = true)
        => CheckingDisabledFixture.Request(type, dnssecOk: dnssecOk);

    public async ValueTask DisposeAsync()
    {
        await Processor.DisposeAsync().ConfigureAwait(true);
        await Epoch.DisposeAsync().ConfigureAwait(true);
    }
    internal sealed class Source(CheckingDisabledMaterialFixture owner) : IDnssecUpstream
    {
        internal ConcurrentQueue<DnsQuestion> Calls { get; } = new();
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken token)
        {
            Calls.Enqueue(question);
            if (owner.Override is { } operation) return operation(question, server, token);
            var record = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 42]);
            return ValueTask.FromResult(Reply(question, server, [record, owner.Signature(record)]));
        }
    }
}
