using System.Collections.Concurrent;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class TrustEpochFixture : IAsyncDisposable
{
    internal TrustEpochFixture()
    {
        Refresh = Anchors.Create();
        KeySigner = Anchors.Keys.A; DataSigner = Anchors.Keys.A;
    }

    internal AnchorRefreshFixture Anchors { get; } = new();
    internal DnssecAnchorRefresher Refresh { get; }
    internal IDnssecSigningKey KeySigner { get; set; }
    internal IDnssecSigningKey DataSigner { get; set; }
    internal DnssecChainFixture.CountingVerifier Verifier { get; } = new();
    internal ConcurrentQueue<DnsQuestion> Calls { get; } = new();
    internal DnsQuestion Question { get; } = new(DnsName.Parse("www.example."), 1, 1);
    internal byte LastOctet { get; set; } = 1;
    internal uint DataTtl { get; set; } = 300;
    internal Func<DnsQuestion, DnsServerEndpoint, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Override { get; set; }
    private readonly List<DnssecTrustEpochResolver> resolvers = [];

    internal DnssecTrustEpochResolver Create(DnssecTrustEpochPolicy? policy = null, IDnssecSignatureVerifier? verifier = null)
    {
        var result = new DnssecTrustEpochResolver(Refresh, new Source(this), verifier ?? Verifier,
            [AnchorRefreshFixture.Server], policy ?? new DnssecTrustEpochPolicy());
        resolvers.Add(result); return result;
    }

    internal DnsUpstreamEvidence Default(DnsQuestion question, DnsServerEndpoint server)
    {
        if (question.Type == 48)
            return Anchors.Reply(question, server, answers: [.. Anchors.Records, Anchors.Keys.Sign(Anchors.Records, KeySigner)]);
        var data = new DnsRecord(question.Name, 1, DataTtl, [192, 0, 2, LastOctet]);
        return Anchors.Reply(question, server, answers: [data, Sign([data])]);
    }

    internal DnsRecord Sign(IReadOnlyList<DnsRecord> records)
    {
        var now = unchecked((uint)Anchors.Keys.Clock.GetUtcNow().ToUnixTimeSeconds());
        return DnssecRrsetSigner.Sign(records, Anchors.Keys.Key(DataSigner), DataSigner, DnssecFixture.Verifier,
            new DnssecSignatureWindow(unchecked(now - 1), unchecked(now + 86400)));
    }

    internal async Task PromoteAsync()
    {
        await Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(false);
        Anchors.Keys.Clock.Advance(TimeSpan.FromDays(30).TotalSeconds);
        await Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(false);
    }

    internal async Task RevokeAsync()
    {
        Anchors.Records = [TrustAnchorFixture.Revoke(Anchors.Keys.Key(Anchors.Keys.A)), Anchors.Keys.Key(Anchors.Keys.B)];
        Anchors.Signatures = [Anchors.Keys.Sign(Anchors.Records, Anchors.Keys.A, Anchors.Records[0])];
        await Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var resolver in resolvers) await resolver.DisposeAsync().ConfigureAwait(false);
        await Refresh.DisposeAsync().ConfigureAwait(false);
        Anchors.Dispose();
    }

    private sealed class Source(TrustEpochFixture owner) : IDnssecUpstream
    {
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            owner.Calls.Enqueue(question);
            return owner.Override is null ? ValueTask.FromResult(owner.Default(question, server))
                : owner.Override(question, server, cancellationToken);
        }
    }
}
