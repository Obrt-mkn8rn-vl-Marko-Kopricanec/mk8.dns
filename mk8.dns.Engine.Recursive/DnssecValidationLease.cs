namespace Mk8.Dns.Engine.Recursive;

internal sealed class DnssecValidationLease(DnssecResolutionClock clock, long received, DateTimeOffset wall,
    uint keyLifetime, uint validity, uint lifetime)
{
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
