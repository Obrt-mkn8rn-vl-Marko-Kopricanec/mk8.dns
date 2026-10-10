using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private readonly DnssecTrustAnchor[]? committedAnchors;

    internal static DnssecIterativeResolver CreateForAnchors(IDnssecUpstream upstream, IDnssecSignatureVerifier verifier,
        IReadOnlyList<DnssecTrustAnchor> anchors, DnsServerEndpoint[] roots, ushort authorityPort,
        DnssecTrustEpochPolicy policy, DnssecResolutionClock clock)
        => new(upstream, verifier, anchors, roots, authorityPort, policy, clock);

    private DnssecIterativeResolver(IDnssecUpstream upstream, IDnssecSignatureVerifier verifier,
        IReadOnlyList<DnssecTrustAnchor> anchors, DnsServerEndpoint[] roots, ushort authorityPort,
        DnssecTrustEpochPolicy policy, DnssecResolutionClock clock)
        : this(upstream, verifier, anchors[0], roots, authorityPort, policy.MaximumExchanges,
            policy.MaximumAliasHops, policy.MaximumVerificationAttempts, clock)
    {
        committedAnchors = [.. anchors];
        minimisation = policy.Minimisation;
        captureClientProof = policy.CaptureClientProof;
    }
}
