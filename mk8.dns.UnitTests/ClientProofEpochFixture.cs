using System.Collections.Concurrent;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class ClientProofEpochFixture : IAsyncDisposable
{
    private readonly List<(TaskCompletionSource<DnsUpstreamEvidence> Held, DnsUpstreamEvidence Reply)> held = [];
    internal ClientProofEpochFixture(bool coalesced = false, int workers = 2, int requests = 8,
        DnssecTrustEpochPolicy? policy = null)
    {
        Clock = new ClientResponseClock(Anchors.Keys.Clock);
        Timers.WallTime = Anchors.Keys.Clock.GetUtcNow();
        Refresh = new DnssecAnchorRefresher(Anchors.Keys.Origin, Anchors.Store, Anchors.Upstream,
            DnssecFixture.Verifier, AnchorRefreshFixture.Server, Clock);
        var limits = policy ?? new DnssecTrustEpochPolicy(maximumActiveRequests: requests);
        var source = new Source(this);
        Resolver = coalesced
            ? DnssecTrustEpochResolver.CreateWithClientProofAndCoalescing(Refresh, source, Verifier,
                [AnchorRefreshFixture.Server], limits, new DnssecWorkPolicy(workers, 8, TimeSpan.FromSeconds(1)), Timers)
            : DnssecTrustEpochResolver.CreateWithClientProof(Refresh, source, Verifier, [AnchorRefreshFixture.Server], limits);
    }

    internal AnchorRefreshFixture Anchors { get; } = new();
    internal ClientResponseClock Clock { get; }
    internal RecursiveCacheClock Timers { get; } = new();
    internal DnssecAnchorRefresher Refresh { get; }
    internal DnssecTrustEpochResolver Resolver { get; }
    internal DnssecChainFixture.CountingVerifier Verifier { get; } = new();
    internal ConcurrentQueue<DnsQuestion> Calls { get; } = new();
    internal DnsQuestion Question { get; } = ClientProofFixture.Question();
    internal uint DataTtl { get; set; } = 300;
    internal byte LastOctet { get; set; } = 1;
    internal bool ShortCandidate { get; set; }
    internal Func<DnsQuestion, DnsServerEndpoint, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Override { get; set; }

    internal TaskCompletionSource<DnsUpstreamEvidence> Hold(DnsQuestion question)
    {
        var completion = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        held.Add((completion, Default(question, AnchorRefreshFixture.Server)));
        return completion;
    }

    internal DnsUpstreamEvidence Default(DnsQuestion question, DnsServerEndpoint server)
    {
        if (question.Type == 48) return Anchors.Reply(question, server);
        // Reserved documentation addresses are finite signed test vectors.
        byte[] value = question.Type == 28 ? [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, LastOctet]
            : [192, 0, 2, LastOctet];
        var record = new DnsRecord(question.Name, question.Type, DataTtl, value);
        var signature = DnssecRrsetSigner.Sign([record], Anchors.Keys.Key(Anchors.Keys.A), Anchors.Keys.A,
            DnssecFixture.Verifier, new DnssecSignatureWindow(99, 10000));
        return Anchors.Reply(question, server, answers: ShortCandidate
            ? [record, signature, signature.WithTtl(3)] : [record, signature]);
    }

    internal void Advance(double seconds)
    {
        Anchors.Keys.Clock.Advance(seconds);
        Timers.WallTime = Anchors.Keys.Clock.GetUtcNow();
        Timers.Set(TimeSpan.FromSeconds(Anchors.Keys.Clock.GetTimestamp() / (double)Anchors.Keys.Clock.TimestampFrequency));
    }

    public async ValueTask DisposeAsync()
    {
        Clock.BeforeTimestamp = null;
        var closing = Resolver.DisposeAsync().AsTask();
        foreach (var (Held, Reply) in held) Held.TrySetResult(Reply);
        try { await closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
        finally
        {
            await Refresh.DisposeAsync().ConfigureAwait(true);
            Anchors.Dispose();
        }
    }

    private sealed class Source(ClientProofEpochFixture owner) : IDnssecUpstream
    {
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken token)
        {
            owner.Calls.Enqueue(question);
            return owner.Override is null ? ValueTask.FromResult(owner.Default(question, server)) : owner.Override(question, server, token);
        }
    }
}
