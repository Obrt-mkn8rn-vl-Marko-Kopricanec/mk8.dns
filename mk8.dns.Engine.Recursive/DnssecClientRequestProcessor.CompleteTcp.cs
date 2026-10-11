namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientRequestProcessor
{
    private readonly bool requireCompleteTcp;

    // Oversized TCP answers become empty SERVFAIL, not partial authenticated data.
    // UDP still uses the original codec's TC/AD policy. Dependencies stay borrowed.
    public static DnssecClientRequestProcessor CreateWithCompleteTcpAnswers(DnssecTrustEpochResolver source,
        DnssecClientAccessPolicy policy, int maximumRequests = 64)
        => new(source, policy, maximumRequests, requireCompleteTcp: true);

    private DnssecClientRequestProcessor(DnssecTrustEpochResolver source, DnssecClientAccessPolicy policy,
        int maximumRequests, bool requireCompleteTcp) : this(source, policy, maximumRequests)
    {
        this.requireCompleteTcp = requireCompleteTcp;
    }
}
