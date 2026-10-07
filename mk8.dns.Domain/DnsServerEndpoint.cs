namespace Mk8.Dns.Domain;

public sealed class DnsServerEndpoint : IEquatable<DnsServerEndpoint>
{
    private readonly byte[] address;

    public DnsServerEndpoint(ReadOnlySpan<byte> address, ushort port = 53)
    {
        if (port == 0 || address.Length is not (4 or 16) || address.IndexOfAnyExcept((byte)0) < 0
            || address.Length == 4 && (address[0] is >= 224 or 0)
            || address.Length == 16 && (address[0] == 255 || address[..12].SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255 })))
            throw new ArgumentException("A DNS upstream needs a specific unicast IPv4 or unmapped IPv6 address and port.", nameof(address));
        this.address = address.ToArray();
        Port = port;
    }

    public ushort Port { get; }
    public byte[] GetAddress() => (byte[])address.Clone();
    public bool Equals(DnsServerEndpoint? other) => other is not null && Port == other.Port && address.AsSpan().SequenceEqual(other.address);
    public override bool Equals(object? obj) => obj is DnsServerEndpoint other && Equals(other);
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(address);
        hash.Add(Port);
        return hash.ToHashCode();
    }
}
