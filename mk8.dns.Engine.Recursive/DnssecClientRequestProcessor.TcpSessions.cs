namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientRequestProcessor
{
    internal bool RequiresCompleteTcpAnswers => requireCompleteTcp;

    internal bool AdmitsTcpPeer(byte[] peer)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            return policy.Allows(peer);
        }
    }
}
