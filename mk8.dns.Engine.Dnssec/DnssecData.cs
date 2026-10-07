using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

internal static class DnssecData
{
    internal static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Invalid bounded uncompressed DNSSEC data.");
    }

    internal static DnsName ReadName(ReadOnlySpan<byte> data, ref int offset)
    {
        var start = offset;
        while (true)
        {
            Require(offset < data.Length);
            var length = data[offset++];
            Require(length <= 63 && length <= data.Length - offset);
            offset += length;
            Require(offset - start <= 255);
            if (length == 0)
                break;
        }
        return DnsName.FromWire(data[start..offset]);
    }

    internal static void LowerName(Span<byte> data, ref int offset)
    {
        var start = offset;
        _ = ReadName(data, ref offset);
        var canonical = DnsName.FromWire(data[start..offset]).ToWire();
        canonical.CopyTo(data[start..offset]);
    }

    internal static bool IsWildcard(DnsName name)
    {
        var wire = name.ToWire();
        return wire.Length >= 3 && wire[0] == 1 && wire[1] == (byte)'*';
    }

    internal static DnsName SignedOwner(DnsName name, byte labels)
    {
        Require(labels <= name.LabelCount);
        if (labels == name.LabelCount)
            return name;
        while (name.LabelCount > labels)
            name = name.Parent;
        return name.PrependLabel([(byte)'*']);
    }
}
