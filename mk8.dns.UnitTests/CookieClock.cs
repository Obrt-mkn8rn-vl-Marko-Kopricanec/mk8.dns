namespace Mk8.Dns.UnitTests;

internal sealed class CookieClock(long seconds) : TimeProvider
{
    private long seconds = seconds;
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Volatile.Read(ref seconds));
    internal void Advance(long value) => Interlocked.Add(ref seconds, value);
}
