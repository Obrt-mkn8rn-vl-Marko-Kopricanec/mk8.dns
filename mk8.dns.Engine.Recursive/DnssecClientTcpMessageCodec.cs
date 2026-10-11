using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

// A complete-message policy over the existing fresh authenticated codec. This
// neither expands the DNS frame nor certifies a connection or later delivery.
public static class DnssecClientTcpMessageCodec
{
    public static bool TryEncode(DnsQuery query, DnssecResolutionResult result, bool recursionAvailable,
        bool authenticatedDataAllowed, out byte[] message)
    {
        message = [];
        if (!DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable,
            authenticatedDataAllowed, out var encoded) || !IsComplete(encoded))
        {
            return false;
        }
        message = encoded;
        return true;
    }

    internal static bool IsComplete(byte[] message) => (BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(2)) & 0x0200) == 0;
}
