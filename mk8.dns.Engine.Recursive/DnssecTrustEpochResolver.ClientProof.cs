using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecTrustEpochResolver
{
    public static DnssecTrustEpochResolver CreateWithClientProof(DnssecAnchorRefresher refresher, IDnssecUpstream upstream,
        IDnssecSignatureVerifier verifier, IEnumerable<DnsServerEndpoint> roots, DnssecTrustEpochPolicy policy,
        ushort authorityPort = 53)
        => new(refresher, upstream, verifier, roots, ClientProofPolicy(policy), authorityPort);

    public static DnssecTrustEpochResolver CreateWithClientProofAndCoalescing(DnssecAnchorRefresher refresher,
        IDnssecUpstream upstream, IDnssecSignatureVerifier verifier, IEnumerable<DnsServerEndpoint> roots,
        DnssecTrustEpochPolicy policy, DnssecWorkPolicy workPolicy, TimeProvider time, ushort authorityPort = 53)
        => CreateWithCoalescing(refresher, upstream, verifier, roots, ClientProofPolicy(policy), workPolicy, time, authorityPort);

    private static DnssecTrustEpochPolicy ClientProofPolicy(DnssecTrustEpochPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.FailureCache is not null)
            throw new ArgumentException("Client-proof cohorts do not compose resolution-failure hold-down.", nameof(policy));
        return policy.WithClientProof();
    }

    private async ValueTask<DnssecResolutionResult> DeliverClientProofAsync(DeliveryRequest request,
        DnssecResolutionResult result, long received, CancellationToken token)
    {
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
                    var delivery = DnssecResolutionWork.Failure(result.Question);
                    if (!closing && ReferenceEquals(current, request.Profile))
                    {
                        if (result.Outcome != DnssecResolutionOutcome.Authenticated)
                        {
                            delivery = AgeDelivery(result, received);
                        }
                        else if (result.Lease?.IsValid() == true)
                        {
                            var limit = refresher.Clock.Age(result.AuthenticatedTtl, received, refresher.Clock.GetTimestamp());
                            delivery = CachingDnssecResolver.PrepareClientProofDelivery(result, limit)
                                ?? DnssecResolutionWork.Failure(result.Question);
                        }
                    }
                    // Materialization reads the borrowed clock. An external ACK may
                    // retire this cohort during those reads, even for identical pins.
                    token.ThrowIfCancellationRequested();
                    if (delivery.Outcome == DnssecResolutionOutcome.Authenticated && delivery.Lease?.IsValid() != true)
                        delivery = DnssecResolutionWork.Failure(result.Question);
                    if (!closing) { RequireUsable(); Synchronise(); }
                    cleanup = request.Profile.Cleanup;
                    if (cleanup?.IsCompleted != false)
                    {
                        if (closing || !ReferenceEquals(current, request.Profile))
                        {
                            delivery = DnssecResolutionWork.Failure(result.Question);
                        }
                        CompleteRequest(request);
                        return delivery;
                    }
                }
            }
            // Preserve the old request charge through actual retired work cleanup.
            if (cleanup is not null) await cleanup.ConfigureAwait(false);
        }
    }
}
