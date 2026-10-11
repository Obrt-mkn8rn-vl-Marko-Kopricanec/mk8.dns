namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientRequestProcessor
{
    private readonly NonValidatingIterativeResolver? checkingDisabledSource;
    private readonly DnssecResolutionClock? checkingDisabledClock;

    // Explicit ordinary CD1/DO0 path. This source has no authentication authority,
    // proof cache or validation epoch. The caller owns both resolvers and clock.
    public static DnssecClientRequestProcessor CreateWithCheckingDisabledSource(DnssecTrustEpochResolver source,
        NonValidatingIterativeResolver checkingDisabledSource, DnssecClientAccessPolicy policy, TimeProvider time,
        bool completeTcpAnswers = false, int maximumRequests = 64)
    {
        ArgumentNullException.ThrowIfNull(checkingDisabledSource);
        ArgumentNullException.ThrowIfNull(time);
        return new(source, checkingDisabledSource, policy, time, completeTcpAnswers, maximumRequests);
    }

    private DnssecClientRequestProcessor(DnssecTrustEpochResolver source, NonValidatingIterativeResolver uncheckedSource,
        DnssecClientAccessPolicy policy, TimeProvider time, bool completeTcpAnswers, int maximumRequests)
        : this(source, policy, maximumRequests)
    {
        checkingDisabledSource = uncheckedSource;
        checkingDisabledClock = new DnssecResolutionClock(time);
        requireCompleteTcp = completeTcpAnswers;
    }
}
