namespace Mk8.Dns.UnitTests;

internal sealed class ClientResponseClock(DnssecChainFixture.ClockProvider source) : TimeProvider
{
    internal int Reads { get; set; }
    internal Action<int>? BeforeTimestamp { get; set; }
    public override long TimestampFrequency => source.TimestampFrequency;
    public override DateTimeOffset GetUtcNow() => source.GetUtcNow();
    public override long GetTimestamp()
    {
        BeforeTimestamp?.Invoke(++Reads);
        return source.GetTimestamp();
    }
}
