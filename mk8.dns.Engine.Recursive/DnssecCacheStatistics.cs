namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecCacheStatistics
{
    internal DnssecCacheStatistics(int entries, long payloadBytes, int activeRequests, long hits, long misses,
        long admissionRejections, long evictions, long expirations)
    {
        Entries = entries; PayloadBytes = payloadBytes; ActiveRequests = activeRequests; Hits = hits; Misses = misses;
        AdmissionRejections = admissionRejections; Evictions = evictions; Expirations = expirations;
    }
    public int Entries { get; }
    public long PayloadBytes { get; }
    public int ActiveRequests { get; }
    public long Hits { get; }
    public long Misses { get; }
    public long AdmissionRejections { get; }
    public long Evictions { get; }
    public long Expirations { get; }
}
