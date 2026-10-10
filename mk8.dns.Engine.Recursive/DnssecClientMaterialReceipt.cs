using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

// A flat material-age receipt: no source work, keys or validator ownership.
internal sealed class DnssecClientMaterialReceipt
{
    private readonly long received;
    private readonly DateTimeOffset wall;

    internal DnssecClientMaterialReceipt(DnssecResolutionClock clock, long received, DateTimeOffset wall)
    {
        Clock = clock;
        this.received = received;
        this.wall = wall;
    }

    internal DnssecResolutionClock Clock { get; }
    internal (long Timestamp, DateTimeOffset Wall) Read() => (Clock.GetTimestamp(), Clock.GetUtcNow());

    internal uint Age(uint ttl, (long Timestamp, DateTimeOffset Wall) now)
    {
        var monotonic = Clock.Age(ttl, received, now.Timestamp);
        var elapsedWall = Math.Ceiling(Math.Max(0, (now.Wall - wall).TotalSeconds));
        var wallLeft = elapsedWall >= ttl ? 0 : ttl - (uint)elapsedWall;
        return Math.Min(monotonic, wallLeft);
    }

    internal DnsRecord Age(DnsRecord record, (long Timestamp, DateTimeOffset Wall) now, uint lifetime)
        => record.WithTtl(Math.Min(lifetime, Age(record.Ttl, now)));
}
