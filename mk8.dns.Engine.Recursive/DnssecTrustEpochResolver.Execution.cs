using System.Runtime.ExceptionServices;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecTrustEpochResolver
{
    private async ValueTask<DnssecResolutionResult> ExecuteAsync(Profile profile, DnsQuestion question, CancellationToken token)
    {
        var request = new DeliveryRequest(profile);
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        try
        {
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (closing) return DnssecResolutionWork.Failure(question);
                RequireUsable(); Synchronise();
                if (!ReferenceEquals(current, profile)) return DnssecResolutionWork.Failure(question);
            }
            var received = refresher.Clock.GetTimestamp();
            ValueTask<DnssecResolutionResult> pending;
            try { pending = profile.ResolveAsync(question, token); }
            catch (ObjectDisposedException error) when ((string.Equals(error.ObjectName, typeof(CachingDnssecResolver).FullName,
                StringComparison.Ordinal) || string.Equals(error.ObjectName, typeof(CoalescingDnssecResolver).FullName,
                StringComparison.Ordinal)) && IsRetired(profile))
            {
                // Only synchronous cache admission: provider faults are captured
                // by its async execution and are awaited outside this catch.
                return DnssecResolutionWork.Failure(question);
            }
            var result = await pending.ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return await DeliverAsync(request, result, received, token).ConfigureAwait(false);
        }
        finally { if (!request.Released) await ReleaseAsync(request).ConfigureAwait(false); }
    }

    private async ValueTask<DnssecResolutionResult> DeliverAsync(DeliveryRequest request, DnssecResolutionResult result,
        long received, CancellationToken token)
    {
        if (policy.CaptureClientProof)
            return await DeliverClientProofAsync(request, result, received, token).ConfigureAwait(false);
        while (true)
        {
            Task? cleanup;
            lock (gate)
            {
                token.ThrowIfCancellationRequested();
                if (!closing) { RequireUsable(); Synchronise(); }
                cleanup = request.Profile.Cleanup;
                if (cleanup?.IsCompleted != false)
                {
                    var delivery = closing || !ReferenceEquals(current, request.Profile)
                        || (result.Outcome == DnssecResolutionOutcome.Authenticated && (result.Lease?.IsValid() != true))
                        ? DnssecResolutionWork.Failure(result.Question) : AgeDelivery(result, received);
                    CompleteRequest(request);
                    return delivery;
                }
            }
            // Recheck the revision and lease after every awaited retirement.
            await cleanup.ConfigureAwait(false);
        }
    }

    private bool IsRetired(Profile profile) { lock (gate) return profile.Retired; }

    private DnssecResolutionResult AgeDelivery(DnssecResolutionResult result, long received)
    {
        var ttl = refresher.Clock.Age(result.AuthenticatedTtl, received, refresher.Clock.GetTimestamp());
        if (result.Lease is not null) ttl = Math.Min(ttl, result.Lease.Remaining());
        return new DnssecResolutionResult(result.Question, result.Outcome, result.ResponseCode, result.Origin,
            result.UnsignedDelegation, ttl, [.. result.Answers.Select(record => record.WithTtl(Math.Min(record.Ttl, ttl)))],
            [.. result.Authority.Select(record => record.WithTtl(Math.Min(record.Ttl, ttl)))], result.Lease);
    }

    private async ValueTask ReleaseAsync(DeliveryRequest request)
    {
        Task? cleanup;
        lock (gate) cleanup = request.Profile.Cleanup;
        try
        {
            // A retired cohort's quota stays owned through its actual cache drain.
            if (cleanup is not null) await cleanup.ConfigureAwait(false);
        }
        finally
        {
            lock (gate) CompleteRequest(request);
        }
    }

    private void CompleteRequest(DeliveryRequest request)
    {
        request.Released = true;
        request.Profile.Active--; activeRequests--;
        RemoveDrainedProfiles();
        if (closing && activeRequests == 0) drained.TrySetResult();
    }

    private async Task FinishDisposalAsync()
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        await drained.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        Profile[] profiles;
        lock (gate) profiles = [.. owned];
        try { await Task.WhenAll(profiles.Select(profile => profile.DisposeAsync().AsTask())).ConfigureAwait(false); }
        finally { lock (gate) RemoveDrainedProfiles(); }
        if (cleanupError is not null) ExceptionDispatchInfo.Capture(cleanupError).Throw();
    }

    private sealed class DeliveryRequest(Profile profile)
    {
        internal Profile Profile { get; } = profile;
        internal bool Released { get; set; }
    }
}
