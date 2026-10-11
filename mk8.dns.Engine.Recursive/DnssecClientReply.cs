namespace Mk8.Dns.Engine.Recursive;

// Historical caller-owned packet snapshot. Reprocess at actual delivery; a
// returned revision or packet is not a reusable epoch/access/validation lease.
public sealed class DnssecClientReply
{
    private readonly byte[] message;

    internal DnssecClientReply(DnssecClientReplyOutcome outcome, byte[] message, long? revision = null)
    {
        Outcome = outcome;
        this.message = (byte[])message.Clone();
        Revision = revision;
    }

    public DnssecClientReplyOutcome Outcome { get; }
    public long? Revision { get; }
    public byte[] GetMessage() => (byte[])message.Clone();
}
