namespace Mk8.Dns.Engine.Recursive;

// Stream write/flush acknowledgement is not client receipt or DNS validation.
public sealed class DnssecClientTcpSessionResult
{
    internal DnssecClientTcpSessionResult(DnssecClientTcpSessionOutcome outcome, int messagesRead, int repliesWritten)
    {
        Outcome = outcome; MessagesRead = messagesRead; RepliesWritten = repliesWritten;
    }

    public DnssecClientTcpSessionOutcome Outcome { get; }
    public int MessagesRead { get; }
    public int RepliesWritten { get; }
}
