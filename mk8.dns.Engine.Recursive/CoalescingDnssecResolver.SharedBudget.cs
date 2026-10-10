using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class CoalescingDnssecResolver
{
    private readonly DnssecSharedWorkBudget? sharedBudget;

    internal CoalescingDnssecResolver(CachingDnssecResolver source, DnssecWorkPolicy policy,
        TimeProvider time, DnssecSharedWorkBudget sharedBudget) : this(source, policy, time)
    {
        ArgumentNullException.ThrowIfNull(sharedBudget);
        this.sharedBudget = sharedBudget;
    }

    private DnssecWorkFlight? CreateFlight(DnsQuestion question)
    {
        if (sharedBudget?.TryAcquire() == false) return null;
        try { return new DnssecWorkFlight(question, time, policy.ResolutionTimeout); }
        catch { sharedBudget?.Release(); throw; }
    }
}
