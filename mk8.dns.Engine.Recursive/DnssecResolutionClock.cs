namespace Mk8.Dns.Engine.Recursive;

internal sealed class DnssecResolutionClock(TimeProvider source) : TimeProvider
{
    private readonly Lock gate = new();
    private bool started;
    private long latest;
    private DateTimeOffset latestWall;
    private bool wallStarted;

    public override long TimestampFrequency => source.TimestampFrequency;
    public override DateTimeOffset GetUtcNow()
    {
        var sample = source.GetUtcNow();
        lock (gate)
        {
            if (!wallStarted || sample > latestWall) latestWall = sample;
            wallStarted = true;
            return latestWall;
        }
    }
    public override long GetTimestamp()
    {
        var sample = source.GetTimestamp();
        lock (gate)
        {
            if (!started || sample > latest) latest = sample;
            started = true;
            return latest;
        }
    }

    internal uint Age(uint ttl, long received, long now)
    {
        var elapsed = Math.Ceiling(Math.Max(0, GetElapsedTime(received, now).TotalSeconds));
        return elapsed >= ttl ? 0 : ttl - (uint)elapsed;
    }
}
