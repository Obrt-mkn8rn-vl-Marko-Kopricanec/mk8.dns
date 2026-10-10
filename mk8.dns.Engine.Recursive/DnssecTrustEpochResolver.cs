using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

// Owns fixed resolver/cache cohorts, not the refresher, transport or verifier.
// Revision checks linearize admission and delivery. Previously returned values
// and independently constructed static profiles are not retroactively revoked.
public sealed partial class DnssecTrustEpochResolver : IAsyncDisposable
{
    private readonly Lock gate = new();
    private readonly DnssecAnchorRefresher refresher;
    private readonly IDnssecUpstream upstream;
    private readonly IDnssecSignatureVerifier verifier;
    private readonly DnsServerEndpoint[] roots;
    private readonly ushort authorityPort;
    private readonly DnssecTrustEpochPolicy policy;
    private readonly HashSet<Profile> owned = [];
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private DnssecAnchorRefreshSnapshot snapshot;
    private Profile? current;
    private Task? disposal;
    private Exception? cleanupError;
    private int activeRequests;
    private long admissionRejections;
    private bool closing;
    private bool faulted;

    public DnssecTrustEpochResolver(DnssecAnchorRefresher refresher, IDnssecUpstream upstream,
        IDnssecSignatureVerifier verifier, IEnumerable<DnsServerEndpoint> roots, DnssecTrustEpochPolicy policy,
        ushort authorityPort = 53)
    {
        ArgumentNullException.ThrowIfNull(refresher);
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(policy);
        if (authorityPort == 0) throw new ArgumentOutOfRangeException(nameof(authorityPort));
        this.roots = [.. roots.Take(17)];
        if (this.roots.Length is < 1 or > 16 || this.roots.Any(server => server is null)
            || this.roots.Distinct().Take(this.roots.Length + 1).Count() != this.roots.Length)
        {
            throw new ArgumentException("Supply one to sixteen distinct bootstrap endpoints.", nameof(roots));
        }

        this.refresher = refresher; this.upstream = upstream; this.verifier = verifier;
        this.policy = policy; this.authorityPort = authorityPort;
        snapshot = refresher.Current;
        CreateProfile();
    }

    public DnssecTrustEpochStatistics Statistics
    {
        get
        {
            lock (gate)
            {
                var cache = current?.Cache.Statistics;
                return new(snapshot.Revision, snapshot.Anchors.Count, activeRequests, owned.Count,
                    owned.Count(profile => profile.Retired), cache?.Entries ?? 0, cache?.PayloadBytes ?? 0,
                    current?.Cache.FailureStatistics.Entries ?? 0, admissionRejections,
                    owned.Sum(profile => profile.Cache.Statistics.ActiveRequests));
            }
        }
    }

    public ValueTask<DnssecResolutionResult> ResolveDnssecAsync(DnsQuestion question, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (question.Name is null) throw new ArgumentException("A trust epoch question needs a name.", nameof(question));
        cancellationToken.ThrowIfCancellationRequested();
        Profile profile;
        lock (gate)
        {
            RequireUsable();
            Synchronise();
            if (current is null || activeRequests == policy.MaximumActiveRequests)
            {
                admissionRejections++;
                return ValueTask.FromResult(DnssecResolutionWork.Failure(question));
            }
            profile = current;
            profile.Active++;
            activeRequests++;
        }
        return ExecuteAsync(profile, question, cancellationToken);
    }

    public void Clear()
    {
        lock (gate) { RequireUsable(); Synchronise(); current?.Cache.Clear(); }
    }

    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            closing = true;
            RetireCurrent();
            if (activeRequests == 0) drained.TrySetResult();
            disposal ??= FinishDisposalAsync();
            return new ValueTask(disposal);
        }
    }

    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(closing, this);
        if (faulted) throw new IOException("Trust epoch adoption is faulted; explicit recovery is required.", cleanupError);
    }

    private sealed class Profile : IAsyncDisposable
    {
        internal Profile(DnssecIterativeResolver resolver, DnssecTrustEpochPolicy policy)
        {
            Cache = policy.FailureCache is null
                ? new CachingDnssecResolver(resolver, policy.MaximumEntries, policy.MaximumPayloadBytes,
                    policy.MaximumActiveRequests, policy.MaximumPositiveTtl, policy.MaximumNegativeTtl)
                : CachingDnssecResolver.CreateWithFailureCache(resolver, policy.FailureCache, policy.MaximumEntries,
                    policy.MaximumPayloadBytes, policy.MaximumActiveRequests, policy.MaximumPositiveTtl, policy.MaximumNegativeTtl);
        }
        internal CachingDnssecResolver Cache { get; }
        internal int Active { get; set; }
        internal bool Retired { get; set; }
        internal Task? Cleanup { get; set; }
        public ValueTask DisposeAsync() => Cache.DisposeAsync();
    }
}
