namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecWorkStatistics
{
    internal DnssecWorkStatistics(int workers, int waiters, long started, long coalesced, long admissionRejections)
    {
        Workers = workers; Waiters = waiters; Started = started; Coalesced = coalesced; AdmissionRejections = admissionRejections;
    }

    public int Workers { get; }
    public int Waiters { get; }
    public long Started { get; }
    public long Coalesced { get; }
    public long AdmissionRejections { get; }
}
