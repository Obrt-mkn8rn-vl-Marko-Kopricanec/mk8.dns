namespace Mk8.Dns.Engine.Recursive;

internal sealed class DnssecValidationLease
{
    private readonly DnssecResolutionClock clock;
    private readonly long received;
    private readonly DateTimeOffset wall;
    private readonly uint keyLifetime;
    private readonly uint validity;
    private readonly uint lifetime;

    internal DnssecValidationLease(DnssecResolutionClock clock, long received, DateTimeOffset wall,
        uint keyLifetime, uint validity, uint lifetime)
    {
        this.clock = clock;
        this.received = received;
        this.wall = wall;
        this.keyLifetime = keyLifetime;
        this.validity = validity;
        this.lifetime = lifetime;
    }

    internal bool UsesClock(DnssecResolutionClock expected) => ReferenceEquals(clock, expected);

    // Projection uses one caller-clock sample for both data and validity fencing.
    // Existing cache/delivery entry points retain their accepted policies below.
    internal uint RemainingAt((long Timestamp, DateTimeOffset Wall) stamp)
    {
        var monotonic = Math.Max(0, clock.GetElapsedTime(received, stamp.Timestamp).TotalSeconds);
        var elapsedWall = Math.Max(0, (stamp.Wall - wall).TotalSeconds);
        if (monotonic >= keyLifetime || elapsedWall >= keyLifetime) return 0;
        var limit = Math.Min(validity, lifetime);
        var wallAge = Math.Ceiling(elapsedWall);
        var wallLeft = wallAge >= limit ? 0 : limit - (uint)wallAge;
        return Math.Min(clock.Age(limit, received, stamp.Timestamp), wallLeft);
    }

    internal bool IsValid()
    {
        var monotonic = Math.Max(0, clock.GetElapsedTime(received, clock.GetTimestamp()).TotalSeconds);
        var elapsedWall = Math.Max(0, (clock.GetUtcNow() - wall).TotalSeconds);
        return monotonic < keyLifetime && elapsedWall < keyLifetime && monotonic <= validity && elapsedWall <= validity;
    }

    internal uint Remaining()
    {
        var monotonic = clock.Age(Math.Min(validity, lifetime), received, clock.GetTimestamp());
        var elapsedWall = Math.Ceiling(Math.Max(0, (clock.GetUtcNow() - wall).TotalSeconds));
        var wallLeft = elapsedWall >= validity ? 0 : validity - (uint)elapsedWall;
        return Math.Min(monotonic, wallLeft);
    }
}
