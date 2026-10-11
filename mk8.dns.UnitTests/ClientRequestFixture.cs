using System.Buffers.Binary;
using Mk8.Dns.Wire;
using Xunit;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal static class ClientRequestFixture
{
    // Documentation addresses are synthetic peer identities, not host allocations.
    internal static byte[] Peer() => [192, 0, 2, 1];
    internal static DnssecClientRequestProcessor Processor(ClientProofEpochFixture f, bool ad = false, int requests = 64)
        => new(f.Resolver, new DnssecClientAccessPolicy([new DnssecClientNetwork([192, 0, 2, 0], 24)], ad), requests);

    internal static byte[] Request(string name = "www.example.", ushort type = 1, ushort flags = 0x0100,
        bool dnssecOk = true, ushort dnsClass = 1, byte version = 0)
    {
        var packet = AuthorityFixture.Query(name, type, 1232, version, flags, dnsClass);
        if (dnssecOk) packet[^4] |= 0x80;
        return packet;
    }
    internal static void AssertError(byte[] request, byte[] message, ushort code)
    {
        var query = DnsMessageCodec.DecodeQuery(request);
        var expected = (byte[])request.Clone();
        var questionEnd = 12 + query.GetQuestionNameWire().Length + 4;
        var flags = (ushort)(0x8080 | (query.Flags & 0x0110) | (code & 15));
        BinaryPrimitives.WriteUInt16BigEndian(expected.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(expected.AsSpan(6), 0);
        BinaryPrimitives.WriteUInt16BigEndian(expected.AsSpan(8), 0);
        BinaryPrimitives.WriteUInt32BigEndian(expected.AsSpan(questionEnd + 5),
            (uint)(code >> 4) << 24 | (query.DnssecOk ? 0x8000U : 0));
        Assert.Equal(expected, message);
    }

}
