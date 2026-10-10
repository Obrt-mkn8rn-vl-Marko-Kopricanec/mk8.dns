using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecTrustEpochResolver
{
    // The concrete refresher publishes immutable acknowledged snapshots. An
    // ambiguous commit or closed source prevents further use of its old profile.
    private void Synchronise()
    {
        DnssecAnchorRefreshSnapshot next;
        try { next = refresher.Current; }
        catch (Exception error) when (error is IOException or ObjectDisposedException)
        {
            faulted = true;
            RetireCurrent();
            throw;
        }
        if (!next.Origin.Equals(snapshot.Origin) || next.Revision < snapshot.Revision)
        {
            faulted = true; RetireCurrent();
            throw new IOException("Committed trust revision or origin changed inconsistently.");
        }
        if (next.Revision != snapshot.Revision)
        {
            RetireCurrent();
            snapshot = next;
        }
        RemoveDrainedProfiles();
        if (faulted) RequireUsable();
        if (current is null) CreateProfile();
    }

    private void CreateProfile()
    {
        if (snapshot.Anchors.Count == 0) return; // No authenticated unsigned fallback.
        if (snapshot.Anchors.Count > DnssecChainValidator.MaximumKeys
            || snapshot.Anchors.Any(pin => !pin.Origin.Equals(snapshot.Origin)))
        {
            throw new IOException("Invalid committed trust anchor set.");
        }
        // Retired cohorts remain owned until their real requests and cache drain.
        if (owned.Count >= policy.MaximumActiveRequests + 1) return;
        var resolver = DnssecIterativeResolver.CreateForAnchors(upstream, verifier, snapshot.Anchors,
            roots, authorityPort, policy, refresher.Clock);
        current = new Profile(resolver, policy);
        owned.Add(current);
    }

    private void RetireCurrent()
    {
        if (current is null) return;
        current.Retired = true;
        // Closing clears both stores and rejects new cache admissions while
        // preserving the cache's actual source-work drain completion.
        current.Cleanup = current.DisposeAsync().AsTask();
        current = null;
    }

    private void RemoveDrainedProfiles()
    {
        foreach (var profile in owned.Where(profile => profile.Retired && profile.Active == 0
            && profile.Cleanup!.IsCompleted).ToArray())
        {
            if (profile.Cleanup!.IsFaulted)
            {
                cleanupError ??= profile.Cleanup.Exception;
                _ = profile.Cleanup.Exception; faulted = true;
            }
            else if (profile.Cleanup.IsCanceled)
            {
                cleanupError ??= new OperationCanceledException("Trust cohort cleanup canceled."); faulted = true;
            }
            owned.Remove(profile);
        }
    }
}
