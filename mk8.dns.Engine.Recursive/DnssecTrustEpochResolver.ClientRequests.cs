using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecTrustEpochResolver
{
    internal bool CapturesClientProof => policy.CaptureClientProof;

    internal bool TryBeginClientQuery(DnsQuestion question, out long revision)
    {
        lock (gate)
        {
            RequireUsable(); Synchronise();
            revision = snapshot.Revision;
            return policy.CaptureClientProof && question.Name.IsSubdomainOf(snapshot.Origin);
        }
    }

    internal bool TryEncodeClientReply(DnsQuery query, DnssecResolutionResult result, long revision, bool tcp,
        bool authenticatedDataAllowed, out byte[] message)
    {
        message = [];
        lock (gate)
        {
            if (closing) return false;
            RequireUsable(); Synchronise();
            if (!policy.CaptureClientProof || snapshot.Revision != revision) return false;
            var accepted = DnssecClientMessageCodec.TryEncode(query, result, tcp, recursionAvailable: true,
                authenticatedDataAllowed, out var encoded);
            // Encoding reads caller-owned clocks. No clock read follows this ACK fence.
            RequireUsable(); Synchronise();
            if (!accepted || snapshot.Revision != revision) return false;
            message = encoded;
            return true;
        }
    }
}
