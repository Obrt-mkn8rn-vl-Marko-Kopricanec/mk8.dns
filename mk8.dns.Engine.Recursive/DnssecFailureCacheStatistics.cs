namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecFailureCacheStatistics
{
    internal DnssecFailureCacheStatistics(int entries, long payloadBytes, long hits, long stores,
        long evictions, long expirations, long admissionRejections)
    {
        Entries = entries; PayloadBytes = payloadBytes; Hits = hits; Stores = stores;
        Evictions = evictions; Expirations = expirations; AdmissionRejections = admissionRejections;
    }

    public int Entries { get; }
    public long PayloadBytes { get; }
    public long Hits { get; }
    public long Stores { get; }
    public long Evictions { get; }
    public long Expirations { get; }
    public long AdmissionRejections { get; }
}
