using System.Security.Cryptography;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure;

public sealed class TsigKey : IDisposable
{
    private readonly Lock sync = new();
    private readonly byte[] secret;
    private readonly DnsName[] zones;
    private readonly byte[][] peers;
    private bool disposed;

    public TsigKey(DnsName name, byte[] secret, IEnumerable<DnsName> zones, IEnumerable<byte[]> peers, byte minimumMacBytes = 16)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(zones);
        ArgumentNullException.ThrowIfNull(peers);
        var origins = zones.Take(17).ToArray();
        var addresses = peers.Take(17).Select(peer => (byte[])peer.Clone()).ToArray();
        if (name.LabelCount == 0 || name.ToWire().Length > 64 || secret.Length is < 16 or > 64 || minimumMacBytes is < 16 or > 32
            || origins.Length is 0 or > 16 || origins.Any(origin => origin is null) || origins.Distinct().Count() != origins.Length
            || addresses.Length is 0 or > 16 || addresses.Any(peer => peer.Length is not (4 or 16))
            || addresses.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count() != addresses.Length)
            throw new ArgumentException("Invalid TSIG key, exact zone or source scope.", nameof(name));
        Name = name;
        MinimumMacBytes = minimumMacBytes;
        this.secret = (byte[])secret.Clone();
        this.zones = origins;
        this.peers = addresses;
    }

    public DnsName Name { get; }
    public byte MinimumMacBytes { get; }

    internal TsigKey Copy()
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return new TsigKey(Name, secret, zones, peers, MinimumMacBytes);
        }
    }

    internal byte[] Hash(ReadOnlySpan<byte> input)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return HMACSHA256.HashData(secret, input);
        }
    }

    internal bool Contains(DnsName origin) => zones.Contains(origin);
    internal bool AllowsPeer(ReadOnlySpan<byte> peer)
    {
        foreach (var address in peers)
            if (peer.SequenceEqual(address))
                return true;
        return false;
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed)
                return;
            disposed = true;
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
