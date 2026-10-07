namespace Mk8.Dns.Engine.Dnssec;

public static class NsecBitmap
{
    public static byte[] Encode(IEnumerable<ushort> types)
    {
        ArgumentNullException.ThrowIfNull(types);
        var items = types.Take(65_537).ToArray();
        if (items.Length is 0 or > 65_536 || items.Any(IsPseudoType))
            throw new ArgumentException("Invalid zone type bitmap input.", nameof(types));
        using var output = new MemoryStream();
        foreach (var group in items.Distinct().Order().GroupBy(type => type >> 8))
        {
            var values = group.ToArray();
            var bitmap = new byte[(values[^1] & 255) / 8 + 1];
            foreach (var type in values)
                bitmap[(type & 255) / 8] |= (byte)(0x80 >> (type & 7));
            output.WriteByte((byte)group.Key);
            output.WriteByte((byte)bitmap.Length);
            output.Write(bitmap);
        }
        return output.ToArray();
    }

    public static ushort[] Decode(ReadOnlySpan<byte> bitmap)
    {
        DnssecData.Require(!bitmap.IsEmpty && bitmap.Length <= 8704);
        List<ushort> types = [];
        var last = -1;
        for (var offset = 0; offset < bitmap.Length;)
        {
            DnssecData.Require(bitmap.Length - offset >= 2);
            var window = bitmap[offset++];
            var length = bitmap[offset++];
            DnssecData.Require(window > last && length is >= 1 and <= 32 && length <= bitmap.Length - offset && bitmap[offset + length - 1] != 0);
            for (var octet = 0; octet < length; octet++)
                for (var bit = 0; bit < 8; bit++)
                {
                    var type = (ushort)((window << 8) + octet * 8 + bit);
                    if ((bitmap[offset + octet] & (0x80 >> bit)) != 0 && !IsPseudoType(type))
                        types.Add(type);
                }
            offset += length;
            last = window;
        }
        return types.ToArray();
    }

    private static bool IsPseudoType(ushort type) => type is 0 or 41 or (>= 249 and <= 255);
}
