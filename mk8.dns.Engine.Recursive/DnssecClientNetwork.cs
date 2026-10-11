namespace Mk8.Dns.Engine.Recursive;

// Caller-configured canonical network bytes. These are access grants, not
// authentication of a transport peer or evidence that an address is allocated.
public sealed class DnssecClientNetwork
{
    private readonly byte[] address;

    public DnssecClientNetwork(ReadOnlySpan<byte> address, int prefixLength)
    {
        if (address.Length is not (4 or 16))
            throw new ArgumentException("Supply four or sixteen network address bytes.", nameof(address));
        if (prefixLength < 0 || prefixLength > address.Length * 8)
            throw new ArgumentOutOfRangeException(nameof(prefixLength), "The prefix must fit the address family.");
        for (var index = 0; index < address.Length; index++)
        {
            var mask = Mask(prefixLength, index);
            if ((address[index] & ~mask) != 0)
                throw new ArgumentException("Network host bits must be zero.", nameof(address));
        }
        this.address = address.ToArray();
        PrefixLength = prefixLength;
    }

    public int PrefixLength { get; }
    public byte[] GetAddress() => (byte[])address.Clone();
    internal string Identity => Convert.ToHexString(address) + "/" + PrefixLength.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public bool Contains(ReadOnlySpan<byte> peer)
    {
        if (peer.Length != address.Length) return false;
        for (var index = 0; index < address.Length; index++)
            if ((peer[index] & Mask(PrefixLength, index)) != address[index]) return false;
        return true;
    }

    private static int Mask(int prefix, int index) => (255 << (8 - Math.Clamp(prefix - (index * 8), 0, 8))) & 255;
}
