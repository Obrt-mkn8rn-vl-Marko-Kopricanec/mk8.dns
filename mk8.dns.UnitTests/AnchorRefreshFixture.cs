using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class AnchorRefreshFixture : IDisposable
{
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    internal static DnsServerEndpoint Server { get; } = new([127, 0, 0, 1], 5300);
    internal TrustAnchorFixture Keys { get; } = new();
    internal MemoryStore Store { get; }
    internal Source Upstream { get; }
    internal DnsRecord[] Records { get; set; }
    internal DnsRecord[]? Signatures { get; set; }

    internal AnchorRefreshFixture()
    {
        Records = [Keys.Key(Keys.A), Keys.Key(Keys.B)];
        Store = new MemoryStore(Keys.Tracker(Keys.A));
        Upstream = new Source(this);
    }

    internal DnssecAnchorRefresher Create(IDnssecSignatureVerifier? verifier = null)
        => new(Keys.Origin, Store, Upstream, verifier ?? DnssecFixture.Verifier, Server, Keys.Clock);

    internal DnsUpstreamEvidence Reply(DnsQuestion? question = null, DnsServerEndpoint? server = null,
        ushort flags = 0x8430, byte version = 0, DnsRecord[]? authority = null, DnsRecord[]? answers = null)
        => new(question ?? new DnsQuestion(Keys.Origin, 48, 1), server ?? Server, 1, flags, (ushort)(flags & 15),
hasEdns: true, 1232, version, 0x8000, answers ?? [.. Records, .. Signatures ?? [Keys.Sign(Records, Keys.A)]], authority ?? [], []);

    public void Dispose() => Keys.Dispose();

    internal sealed class Source(AnchorRefreshFixture owner) : IDnssecUpstream
    {
        internal int Calls { get; private set; }
        internal Func<DnsQuestion, DnsServerEndpoint, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Override { get; set; }
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            Calls++;
            return Override is null ? ValueTask.FromResult(owner.Reply()) : Override(question, server, cancellationToken);
        }
    }

    internal sealed class MemoryStore(DnssecTrustAnchorTracker initial) : IDnssecAnchorCheckpointStore
    {
        internal DnssecStoredAnchorCheckpoint State { get; private set; } = new(initial.Origin, 1, initial.CreateCheckpoint());
        internal int Commits { get; private set; }
        internal Action? BeforeCommit { get; set; }
        internal Action? AfterCommit { get; set; }
        internal long? ReplyRevision { get; set; }
        public DnssecStoredAnchorCheckpoint ReadCommitted() => State;
        public long Commit(long expectedRevision, DnssecTrustAnchorTracker candidate, CancellationToken cancellationToken)
        {
            BeforeCommit?.Invoke(); cancellationToken.ThrowIfCancellationRequested();
            if (expectedRevision != State.Revision) throw new InvalidOperationException("Controlled revision conflict.");
            State = new DnssecStoredAnchorCheckpoint(candidate.Origin, expectedRevision + 1, candidate.CreateCheckpoint());
            Commits++;
            AfterCommit?.Invoke();
            return ReplyRevision ?? State.Revision;
        }
    }
}
