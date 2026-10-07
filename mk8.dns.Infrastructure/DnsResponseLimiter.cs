using Mk8.Dns.Application.Abstractions;

namespace Mk8.Dns.Infrastructure;

public sealed class DnsResponseLimiter : IDnsResponseLimiter
{
    private readonly Lock sync = new();
    private readonly TimeProvider clock;
    private readonly Dictionary<(ulong Prefix, bool Ipv6), LinkedListNode<Bucket>> prefixes = [];
    private readonly LinkedList<Bucket> recent = new();
    private readonly int packetRate;
    private readonly int packetBurst;
    private readonly int byteRate;
    private readonly int byteBurst;
    private readonly int globalPacketRate;
    private readonly int globalPacketBurst;
    private readonly int globalByteRate;
    private readonly int globalByteBurst;
    private readonly int maximumPrefixes;
    private readonly double idleSeconds;
    private readonly Bucket global;
    private readonly Bucket overflow;
    private long admitted;
    private long dropped;

    public DnsResponseLimiter(TimeProvider clock, int responsesPerSecond = 100, int responseBurst = 200,
        int bytesPerSecond = 51_200, int byteBurst = 102_400, int globalResponsesPerSecond = 10_000,
        int globalResponseBurst = 20_000, int globalBytesPerSecond = 5_120_000, int globalByteBurst = 10_240_000,
        int maximumPrefixes = 4096)
    {
        ArgumentNullException.ThrowIfNull(clock);
        Check(responsesPerSecond, 1, 1_000_000, nameof(responsesPerSecond));
        Check(responseBurst, 1, 1_000_000, nameof(responseBurst));
        Check(bytesPerSecond, 1, 1_000_000_000, nameof(bytesPerSecond));
        Check(byteBurst, 512, 1_000_000_000, nameof(byteBurst));
        Check(globalResponsesPerSecond, 1, 1_000_000, nameof(globalResponsesPerSecond));
        Check(globalResponseBurst, 1, 1_000_000, nameof(globalResponseBurst));
        Check(globalBytesPerSecond, 1, 1_000_000_000, nameof(globalBytesPerSecond));
        Check(globalByteBurst, 512, 1_000_000_000, nameof(globalByteBurst));
        Check(maximumPrefixes, 1, 65_536, nameof(maximumPrefixes));
        this.clock = clock;
        packetRate = responsesPerSecond;
        packetBurst = responseBurst;
        byteRate = bytesPerSecond;
        this.byteBurst = byteBurst;
        globalPacketRate = globalResponsesPerSecond;
        globalPacketBurst = globalResponseBurst;
        globalByteRate = globalBytesPerSecond;
        this.globalByteBurst = globalByteBurst;
        this.maximumPrefixes = maximumPrefixes;
        idleSeconds = Math.Max(60, Math.Max((double)packetBurst / packetRate, (double)byteBurst / byteRate));
        var now = clock.GetTimestamp();
        global = new Bucket(default, now, globalPacketBurst, globalByteBurst);
        overflow = new Bucket(default, now, packetBurst, byteBurst);
    }

    public bool TryAdmit(ReadOnlySpan<byte> peerAddress, int responseBytes)
    {
        var key = Prefix(peerAddress);
        Check(responseBytes, 12, ushort.MaxValue, nameof(responseBytes));
        lock (sync)
        {
            var now = clock.GetTimestamp();
            // Reclaim only fully refilled idle budgets; never evict active debt to admit a new source.
            for (var count = 0; count < 64 && recent.First is { } oldest && now > oldest.Value.Seen
                && clock.GetElapsedTime(oldest.Value.Seen, now).TotalSeconds >= idleSeconds; count++)
            {
                prefixes.Remove(oldest.Value.Key);
                recent.RemoveFirst();
            }
            Bucket source;
            if (prefixes.TryGetValue(key, out var node))
            {
                source = node.Value;
                recent.Remove(node);
                recent.AddLast(node);
            }
            else if (prefixes.Count < maximumPrefixes)
            {
                source = new Bucket(key, now, packetBurst, byteBurst);
                prefixes.Add(key, recent.AddLast(source));
            }
            else
                source = overflow;
            source.Seen = Math.Max(source.Seen, now);
            Refill(source, now, packetRate, packetBurst, byteRate, byteBurst);
            Refill(global, now, globalPacketRate, globalPacketBurst, globalByteRate, globalByteBurst);
            if (source.Packets < 1 || source.Bytes < responseBytes || global.Packets < 1 || global.Bytes < responseBytes)
            {
                if (dropped != long.MaxValue)
                    dropped++;
                return false;
            }
            source.Packets--;
            source.Bytes -= responseBytes;
            global.Packets--;
            global.Bytes -= responseBytes;
            if (admitted != long.MaxValue)
                admitted++;
            return true;
        }
    }

    public (long Admitted, long Dropped, int TrackedPrefixes) Statistics
    {
        get
        {
            lock (sync)
                return (admitted, dropped, prefixes.Count);
        }
    }

    private void Refill(Bucket bucket, long now, int packetsPerSecond, int packetsMaximum, int bytesPerSecond, int bytesMaximum)
    {
        if (now <= bucket.Stamp)
            return;
        var elapsed = clock.GetElapsedTime(bucket.Stamp, now).TotalSeconds;
        bucket.Packets = Math.Min(packetsMaximum, bucket.Packets + elapsed * packetsPerSecond);
        bucket.Bytes = Math.Min(bytesMaximum, bucket.Bytes + elapsed * bytesPerSecond);
        bucket.Stamp = now;
    }

    private static (ulong Prefix, bool Ipv6) Prefix(ReadOnlySpan<byte> address)
    {
        if (address.Length is not (4 or 16))
            throw new ArgumentException("UDP budgets require an IPv4 or IPv6 peer address.", nameof(address));
        if (address.Length == 16 && address[..10].IndexOfAnyExcept((byte)0) < 0 && address[10] == 255 && address[11] == 255)
            address = address[12..];
        ulong prefix = 0;
        var octets = address.Length == 4 ? 3 : 7;
        foreach (var octet in address[..octets])
            prefix = (prefix << 8) | octet;
        return (prefix, address.Length == 16);
    }

    private static void Check(int value, int minimum, int maximum, string parameterName)
    {
        if (value < minimum || value > maximum)
            throw new ArgumentOutOfRangeException(parameterName, value, "UDP budget value is outside its supported range.");
    }

    private sealed class Bucket((ulong Prefix, bool Ipv6) key, long stamp, int packets, int bytes)
    {
        internal (ulong Prefix, bool Ipv6) Key { get; } = key;
        internal long Stamp { get; set; } = stamp;
        internal long Seen { get; set; } = stamp;
        internal double Packets { get; set; } = packets;
        internal double Bytes { get; set; } = bytes;
    }
}
