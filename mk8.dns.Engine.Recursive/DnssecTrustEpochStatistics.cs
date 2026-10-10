namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecTrustEpochStatistics
{
    internal DnssecTrustEpochStatistics(long revision, int anchors, int activeRequests, int ownedProfiles,
        int retiredProfiles, int entries, long payloadBytes, int failureEntries, long admissionRejections, int sourceRequests)
    {
        Revision = revision; Anchors = anchors; ActiveRequests = activeRequests; OwnedProfiles = ownedProfiles;
        RetiredProfiles = retiredProfiles; Entries = entries; PayloadBytes = payloadBytes;
        FailureEntries = failureEntries; AdmissionRejections = admissionRejections;
        SourceRequests = sourceRequests;
    }
    public long Revision { get; }
    public int Anchors { get; }
    public int ActiveRequests { get; }
    public int OwnedProfiles { get; }
    public int RetiredProfiles { get; }
    public int Entries { get; }
    public long PayloadBytes { get; }
    public int FailureEntries { get; }
    public long AdmissionRejections { get; }
    public int SourceRequests { get; }
}
