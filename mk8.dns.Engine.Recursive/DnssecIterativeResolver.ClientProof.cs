using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecIterativeResolver
{
    private readonly bool captureClientProof;

    public static DnssecIterativeResolver CreateWithClientProof(IDnssecUpstream upstream, IDnssecSignatureVerifier verifier,
        DnssecTrustAnchor anchor, IEnumerable<DnsServerEndpoint> roots, ushort authorityPort = 53,
        int maximumExchanges = 64, int maximumAliasHops = 16, int maximumVerificationAttempts = 512,
        TimeProvider? time = null, DnsQnameMinimisationPolicy? minimisation = null)
        => new(upstream, verifier, anchor, roots, authorityPort, maximumExchanges, maximumAliasHops,
            maximumVerificationAttempts, time, minimisation);

    private DnssecIterativeResolver(IDnssecUpstream upstream, IDnssecSignatureVerifier verifier,
        DnssecTrustAnchor anchor, IEnumerable<DnsServerEndpoint> roots, ushort authorityPort,
        int maximumExchanges, int maximumAliasHops, int maximumVerificationAttempts, TimeProvider? time,
        DnsQnameMinimisationPolicy? minimisation)
        : this(upstream, verifier, anchor, roots, authorityPort, maximumExchanges, maximumAliasHops, maximumVerificationAttempts, time)
    {
        captureClientProof = true;
        this.minimisation = minimisation;
    }
}
