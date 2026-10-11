using System.Collections.Concurrent;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class CheckingDisabledFixture : IAsyncDisposable
{
    internal CheckingDisabledFixture(int requests = 64, bool complete = false)
    {
        Clock = new ClientResponseClock(Epoch.Anchors.Keys.Clock);
        Upstream = new Source(this);
        Unchecked = new NonValidatingIterativeResolver(Upstream, [AnchorRefreshFixture.Server], time: Epoch.Anchors.Keys.Clock);
        Processor = DnssecClientRequestProcessor.CreateWithCheckingDisabledSource(Epoch.Resolver, Unchecked,
            new DnssecClientAccessPolicy([new DnssecClientNetwork([192, 0, 2, 0], 24)], authenticatedDataAllowed: true),
            Clock, complete, requests);
    }
    internal ClientProofEpochFixture Epoch { get; } = new();
    internal ClientResponseClock Clock { get; }
    internal Source Upstream { get; }
    internal NonValidatingIterativeResolver Unchecked { get; }
    internal DnssecClientRequestProcessor Processor { get; }
    internal Func<DnsQuestion, CancellationToken, ValueTask<DnsAnswer>>? Override { get; set; }
    internal uint Ttl { get; set; } = 300;

    internal DnsAnswer Answer(DnsQuestion question)
    {
        byte[] data = question.Type == 28 ? [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42]
            : question.Type == 48 ? Epoch.Anchors.Keys.Key(Epoch.Anchors.Keys.A).GetData() : [192, 0, 2, 42];
        return new(0, authoritative: true, [new DnsRecord(question.Name, question.Type, Ttl, data)], [], []);
    }
    internal static byte[] Request(ushort type = 1, ushort flags = 0x0130, bool dnssecOk = false)
        => ClientRequestFixture.Request(type: type, flags: flags, dnssecOk: dnssecOk);

    public async ValueTask DisposeAsync()
    {
        Clock.BeforeTimestamp = null;
        await Processor.DisposeAsync().ConfigureAwait(true);
        await Epoch.DisposeAsync().ConfigureAwait(true);
    }

    internal sealed class Source(CheckingDisabledFixture owner) : IDnsUpstream
    {
        internal ConcurrentQueue<DnsQuestion> Calls { get; } = new();
        public ValueTask<DnsAnswer> ExchangeAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken token)
        {
            Calls.Enqueue(question);
            return owner.Override is null ? ValueTask.FromResult(owner.Answer(question)) : owner.Override(question, token);
        }
    }
}
