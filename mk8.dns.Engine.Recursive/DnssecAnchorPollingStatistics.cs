namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecAnchorPollingStatistics
{
    internal DnssecAnchorPollingStatistics(int attempts, int applied, int refused, int busy, bool waiting, bool closing, bool completed)
    {
        Attempts = attempts; Applied = applied; Refused = refused; Busy = busy;
        Waiting = waiting; Closing = closing; Completed = completed;
    }

    public int Attempts { get; }
    public int Applied { get; }
    public int Refused { get; }
    public int Busy { get; }
    public bool Waiting { get; }
    public bool Closing { get; }
    public bool Completed { get; }
}
