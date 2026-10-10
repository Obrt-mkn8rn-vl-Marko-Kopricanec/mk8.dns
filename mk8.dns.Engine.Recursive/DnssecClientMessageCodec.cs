using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Engine.Recursive;

// Encodes already authenticated, proof-producing results only. The caller owns access,
// trust-epoch and delivery policy. Returned bytes are historical; encode again at delivery.
public static class DnssecClientMessageCodec
{
    public static bool TryEncode(DnsQuery query, DnssecResolutionResult result, bool tcp, bool recursionAvailable,
        bool authenticatedDataAllowed, out byte[] message)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(result);
        message = [];
        if (query.Question is not { Class: 1 } question || (query.Flags & ~0x0130) != 0
            || query.EdnsVersion != 0 || query.GetCookieWire() is not null || (query.DnssecOk && !query.HasEdns)
            || !DnssecClientResponseProjection.TryPrepare(result, question, query.DnssecOk, out var snapshot))
        {
            return false;
        }

        var answer = new DnsAnswer(snapshot.ResponseCode, authoritative: false, snapshot.Answers, snapshot.Authority, []);
        var encoded = DnsMessageCodec.EncodeResponse(query, answer, tcp);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(2));
        if (recursionAvailable) flags |= 0x0080;
        // AD is opt-in, requested by DO or AD, and conservatively clear with CD or TC.
        // CD does not authorize validation bypass or returning unsigned/failed data here.
        if (authenticatedDataAllowed && (query.DnssecOk || (query.Flags & 0x0020) != 0)
            && (flags & 0x0210) == 0)
        {
            flags |= 0x0020;
        }
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(2), flags);

        // Encoding can cross a data/key/candidate-window boundary. Never publish stale bytes.
        if (!DnssecClientResponseProjection.TryPrepare(result, question, query.DnssecOk, out var current)
            || current.RemainingTtl < snapshot.RemainingTtl)
        {
            return false;
        }
        message = encoded;
        return true;
    }
}
