namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecFailureCachePolicy
{
    public DnssecFailureCachePolicy(int maximumEntries = 1024, long maximumPayloadBytes = 1048576,
        uint minimumTtl = 5, uint maximumTtl = 300)
    {
        if (maximumEntries is < 1 or > 65536 || maximumPayloadBytes is < 1 or > 16777216
            || minimumTtl is < 1 or > 300 || maximumTtl < minimumTtl || maximumTtl > 300)
            throw new ArgumentOutOfRangeException(nameof(maximumEntries), "Invalid resolution-failure cache limits.");
        MaximumEntries = maximumEntries; MaximumPayloadBytes = maximumPayloadBytes;
        MinimumTtl = minimumTtl; MaximumTtl = maximumTtl;
    }

    public int MaximumEntries { get; }
    public long MaximumPayloadBytes { get; }
    public uint MinimumTtl { get; }
    public uint MaximumTtl { get; }
}
