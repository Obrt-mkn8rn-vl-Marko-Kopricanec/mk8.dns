using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

// Historical authenticated timing, not an ongoing DNSKEY lease or a scheduler.
// Intervals start at capture; callers must charge acquisition/verification/commit
// and queued time before choosing when to query again.
public sealed class DnssecAnchorProofTiming
{
    internal DnssecAnchorProofTiming(DnsName origin, long seconds, uint originalTtl, uint expirationInterval)
    {
        Origin = origin; CapturedUtc = DateTimeOffset.FromUnixTimeSeconds(seconds);
        OriginalTtl = originalTtl; SignatureExpirationInterval = TimeSpan.FromSeconds(expirationInterval);
        var shortest = Math.Min((long)originalTtl * TimeSpan.TicksPerSecond, SignatureExpirationInterval.Ticks);
        QueryInterval = TimeSpan.FromTicks(Math.Max(TimeSpan.TicksPerHour, Math.Min(TimeSpan.TicksPerDay * 15, shortest / 2)));
        RetryInterval = TimeSpan.FromTicks(Math.Max(TimeSpan.TicksPerHour, Math.Min(TimeSpan.TicksPerDay, shortest / 10)));
    }

    public DnsName Origin { get; }
    public DateTimeOffset CapturedUtc { get; }
    public uint OriginalTtl { get; }
    public TimeSpan SignatureExpirationInterval { get; }
    public TimeSpan QueryInterval { get; }
    public TimeSpan RetryInterval { get; }
}
