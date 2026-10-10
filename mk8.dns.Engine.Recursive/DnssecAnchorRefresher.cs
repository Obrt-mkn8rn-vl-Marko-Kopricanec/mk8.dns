using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

// One explicit fresh acquisition per invocation, with no scheduler or retries.
// Store, transport, verifier, clocks and previously exported static profiles
// remain caller-owned. A stored revision is not an external rollback floor.
public sealed partial class DnssecAnchorRefresher : IAsyncDisposable
{
    private readonly Lock gate = new();
    private readonly IDnssecAnchorCheckpointStore store;
    private readonly IDnssecUpstream upstream;
    private readonly DnsServerEndpoint server;
    private readonly DnssecResolutionClock clock;
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private DnssecTrustAnchorTracker tracker;
    private DnssecAnchorRefreshSnapshot current;
    private bool active;
    private bool closing;
    private bool faulted;
    internal DnssecResolutionClock Clock => clock;

    public DnssecAnchorRefresher(DnsName origin, IDnssecAnchorCheckpointStore store, IDnssecUpstream upstream,
        IDnssecSignatureVerifier verifier, DnsServerEndpoint server, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(server);
        this.store = store; this.upstream = upstream; this.server = server;
        clock = new DnssecResolutionClock(time ?? TimeProvider.System);
        var saved = store.ReadCommitted();
        if (!saved.Origin.Equals(origin)) throw new ArgumentException("Stored anchor origin does not match.", nameof(origin));
        tracker = DnssecTrustAnchorTracker.RestoreCheckpoint(origin, saved.GetCheckpoint(), verifier, clock);
        current = new DnssecAnchorRefreshSnapshot(origin, saved.Revision, tracker.GetTrustAnchors());
    }

    public DnssecAnchorRefreshSnapshot Current
    {
        get { lock (gate) { RequireUsable(); return current; } }
    }

    public ValueTask<DnssecAnchorRefreshOutcome> RefreshAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            RequireUsable();
            if (active) return ValueTask.FromResult(DnssecAnchorRefreshOutcome.Busy);
            active = true;
        }
        return RefreshCoreAsync(cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            closing = true;
            if (!active) drained.TrySetResult();
            return new ValueTask(drained.Task);
        }
    }

    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(closing, this);
        if (faulted) throw new IOException("Anchor refresh adoption is faulted; explicit durable recovery is required.");
    }
}
