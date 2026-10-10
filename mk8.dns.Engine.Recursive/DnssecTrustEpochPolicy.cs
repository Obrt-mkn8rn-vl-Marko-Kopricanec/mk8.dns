namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecTrustEpochPolicy
{
    public DnssecTrustEpochPolicy(int maximumActiveRequests = 64, int maximumEntries = 4096,
        long maximumPayloadBytes = 16777216, uint maximumPositiveTtl = 86400, uint maximumNegativeTtl = 3600,
        int maximumExchanges = 64, int maximumAliasHops = 16, int maximumVerificationAttempts = 512,
        DnssecFailureCachePolicy? failureCache = null, DnsQnameMinimisationPolicy? minimisation = null)
    {
        if (maximumActiveRequests is < 1 or > 256 || maximumEntries is < 1 or > 65536
            || maximumPayloadBytes is < 1 or > 536870912 || maximumPositiveTtl is < 1 or > 604800
            || maximumNegativeTtl is < 1 or > 86400 || maximumNegativeTtl > maximumPositiveTtl
            || maximumExchanges is < 1 or > 256 || maximumAliasHops is < 1 or > 32
            || maximumVerificationAttempts is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumActiveRequests), "Invalid trust epoch budgets.");
        }

        MaximumActiveRequests = maximumActiveRequests; MaximumEntries = maximumEntries;
        MaximumPayloadBytes = maximumPayloadBytes; MaximumPositiveTtl = maximumPositiveTtl;
        MaximumNegativeTtl = maximumNegativeTtl; MaximumExchanges = maximumExchanges;
        MaximumAliasHops = maximumAliasHops; MaximumVerificationAttempts = maximumVerificationAttempts;
        FailureCache = failureCache; Minimisation = minimisation;
    }

    public int MaximumActiveRequests { get; }
    public int MaximumEntries { get; }
    public long MaximumPayloadBytes { get; }
    public uint MaximumPositiveTtl { get; }
    public uint MaximumNegativeTtl { get; }
    public int MaximumExchanges { get; }
    public int MaximumAliasHops { get; }
    public int MaximumVerificationAttempts { get; }
    public DnssecFailureCachePolicy? FailureCache { get; }
    public DnsQnameMinimisationPolicy? Minimisation { get; }

    internal bool CaptureClientProof { get; private init; }

    internal DnssecTrustEpochPolicy WithClientProof()
        => new(MaximumActiveRequests, MaximumEntries, MaximumPayloadBytes, MaximumPositiveTtl, MaximumNegativeTtl,
            MaximumExchanges, MaximumAliasHops, MaximumVerificationAttempts, FailureCache, Minimisation)
        { CaptureClientProof = true };
}
