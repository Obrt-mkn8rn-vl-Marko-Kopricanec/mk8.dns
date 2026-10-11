namespace Mk8.Dns.Engine.Recursive;

public enum DnssecClientTcpSessionOutcome
{
    EndOfStream = 0,
    MessageLimit = 1,
    Denied = 2,
    Stopped = 3,
    Dropped = 4,
}
