namespace Mk8.Dns.UnitTests;

internal sealed class BudgetClock : TimeProvider
{
    private long ticks;
    internal DateTimeOffset WallTime { get; set; } = DateTimeOffset.UnixEpoch;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => Interlocked.Read(ref ticks);
    public override DateTimeOffset GetUtcNow() => WallTime;
    internal void Advance(TimeSpan elapsed) => Interlocked.Add(ref ticks, elapsed.Ticks);
}
