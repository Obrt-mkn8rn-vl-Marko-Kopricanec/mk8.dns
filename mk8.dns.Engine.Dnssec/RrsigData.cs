using System.Buffers.Binary;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

internal sealed class RrsigData
{
    internal required ushort Type { get; init; }
    internal required byte Algorithm { get; init; }
    internal required byte Labels { get; init; }
    internal required uint OriginalTtl { get; init; }
    internal required DnssecSignatureWindow Window { get; init; }
    internal required ushort KeyTag { get; init; }
    internal required DnsName Signer { get; init; }
    internal required byte[] Signature { get; init; }

    internal byte[] Header()
    {
        var signer = Signer.ToWire();
        var data = new byte[18 + signer.Length];
        BinaryPrimitives.WriteUInt16BigEndian(data, Type);
        data[2] = Algorithm;
        data[3] = Labels;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), OriginalTtl);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), Window.Expiration);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12), Window.Inception);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(16), KeyTag);
        signer.CopyTo(data, 18);
        return data;
    }

    internal static RrsigData Decode(DnsRecord record)
    {
        var data = record.GetData();
        DnssecData.Require(record.Type == 46 && data.Length >= 19);
        var offset = 18;
        var signer = DnssecData.ReadName(data, ref offset);
        DnssecData.Require(data.Length - offset == 64 && data[2] == 13);
        return new RrsigData
        {
            Type = BinaryPrimitives.ReadUInt16BigEndian(data),
            Algorithm = data[2],
            Labels = data[3],
            OriginalTtl = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(4)),
            Window = new DnssecSignatureWindow(BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(12)), BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(8))),
            KeyTag = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(16)),
            Signer = signer,
            Signature = data[offset..],
        };
    }
}
