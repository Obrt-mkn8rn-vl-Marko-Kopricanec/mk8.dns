namespace Mk8.Dns.Engine.Recursive;

public sealed class RecursiveCacheStatistics
{
    internal RecursiveCacheStatistics(int entries, long payloadBytes, int activeFlights, int waiters,
        long hits, long misses, long coalesced, long admissionRejections, long evictions, long expirations)
    {
        Entries = entries;
        PayloadBytes = payloadBytes;
        ActiveFlights = activeFlights;
        Waiters = waiters;
        Hits = hits;
        Misses = misses;
        Coalesced = coalesced;
        AdmissionRejections = admissionRejections;
        Evictions = evictions;
        Expirations = expirations;
    }

    public int Entries { get; }
    public long PayloadBytes { get; }
    public int ActiveFlights { get; }
    public int Waiters { get; }
    public long Hits { get; }
    public long Misses { get; }
    public long Coalesced { get; }
    public long AdmissionRejections { get; }
    public long Evictions { get; }
    public long Expirations { get; }
}
