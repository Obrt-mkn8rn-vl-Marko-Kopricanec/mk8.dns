using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.UnitTests;

internal static class ClientMessageFixture
{
    internal static DnsQuery Query(string name = "www.example.", ushort type = 1, ushort flags = 0x0100,
        bool dnssecOk = true, ushort? size = 1232)
    {
        var bytes = AuthorityFixture.Query(name, type, size, flags: flags);
        if (dnssecOk && size.HasValue) bytes[^4] = 0x80;
        return DnsMessageCodec.DecodeQuery(bytes);
    }

    internal static ushort Flags(byte[] message) => BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(2));
    internal static DnsUpstreamEvidence Decode(byte[] message, DnsQuery query)
        => UpstreamMessageCodec.DecodeDnssecResponse(message, query.Id, query.Question!, OnlineDnssecFixture.RootServer).Evidence!;
}
