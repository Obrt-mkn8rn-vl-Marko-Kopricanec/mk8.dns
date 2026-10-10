using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecTrustEpochResolver
{
    private readonly SharedWork? sharedWork;

    public static DnssecTrustEpochResolver CreateWithCoalescing(DnssecAnchorRefresher refresher, IDnssecUpstream upstream,
        IDnssecSignatureVerifier verifier, IEnumerable<DnsServerEndpoint> roots, DnssecTrustEpochPolicy policy,
        DnssecWorkPolicy workPolicy, TimeProvider time, ushort authorityPort = 53)
    {
        ArgumentNullException.ThrowIfNull(workPolicy);
        ArgumentNullException.ThrowIfNull(time);
        return new DnssecTrustEpochResolver(refresher, upstream, verifier, roots, policy, workPolicy, time, authorityPort);
    }

    private DnssecTrustEpochResolver(DnssecAnchorRefresher refresher, IDnssecUpstream upstream,
        IDnssecSignatureVerifier verifier, IEnumerable<DnsServerEndpoint> roots, DnssecTrustEpochPolicy policy,
        DnssecWorkPolicy workPolicy, TimeProvider time, ushort authorityPort)
        : this(refresher, upstream, verifier, roots, policy, authorityPort)
    {
        sharedWork = new SharedWork(workPolicy, time);
        current?.EnableCoalescing(sharedWork);
    }

    // These are software admission observations, not CPU/heap or progress bounds.
    public int ActiveWorkers => sharedWork?.Budget.Active ?? 0;
    public DnssecWorkStatistics? CurrentWorkStatistics
    {
        get { lock (gate) return current?.Work?.Statistics; }
    }

    private sealed class SharedWork(DnssecWorkPolicy policy, TimeProvider time)
    {
        internal DnssecWorkPolicy Policy { get; } = policy;
        internal TimeProvider Time { get; } = time;
        internal DnssecSharedWorkBudget Budget { get; } = new(policy.MaximumWorkers);
    }
}
