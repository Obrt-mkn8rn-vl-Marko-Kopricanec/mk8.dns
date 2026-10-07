using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Infrastructure;

public sealed class TsigService : ITsigService, IDisposable
{
    private static readonly DnsName Algorithm = DnsName.Parse("hmac-sha256.");
    private readonly Lock sync = new();
    private readonly TsigKey[] keys;
    private readonly TimeProvider clock;
    private bool disposed;

    public TsigService(IEnumerable<TsigKey> keys, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(clock);
        List<TsigKey> owned = [];
        try
        {
            foreach (var key in keys.Take(17))
                owned.Add(key.Copy());
            if (owned.Count > 16 || owned.Select(key => key.Name).Distinct().Count() != owned.Count)
                throw new ArgumentException("TSIG keys require at most sixteen distinct identities.", nameof(keys));
            this.keys = [.. owned];
        }
        catch
        {
            foreach (var key in owned)
                key.Dispose();
            throw;
        }
        this.clock = clock;
    }

    public bool IsAvailable
    {
        get
        {
            lock (sync)
                return !disposed && clock.GetUtcNow().ToUnixTimeSeconds() is >= 0 and <= 0xffff_ffff_ffff;
        }
    }

    public ITsigTransaction? Open(ReadOnlySpan<byte> message, ReadOnlySpan<byte> peerAddress)
    {
        if (peerAddress.Length is not (4 or 16))
            throw new ArgumentException("TSIG source requires IPv4 or IPv6.", nameof(peerAddress));
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            var request = TsigMessageCodec.DecodeRequest(message);
            if (request is null)
                return null;
            var seconds = clock.GetUtcNow().ToUnixTimeSeconds();
            if (seconds is < 0 or > 0xffff_ffff_ffff)
                throw new InvalidOperationException("TSIG requires a representable trusted clock.");
            var now = (ulong)seconds;
            var key = keys.FirstOrDefault(key => key.Name.Equals(request.KeyName));
            if (key is null || !request.Algorithm.Equals(Algorithm))
                return new TsigTransaction(request, null, 17, now, false);
            var mac = request.GetMac();
            if (mac.Length is < 16 or > 32)
                throw new FormatException("TSIG MAC length is outside the algorithm bounds.");
            var input = TsigMessageCodec.CreateMacInput(request.GetMessage(), request, [], request.TimeSigned, request.Fudge, request.Error, request.GetOtherData());
            var expected = key.Hash(input);
            if (!CryptographicOperations.FixedTimeEquals(expected.AsSpan(0, mac.Length), mac))
                return new TsigTransaction(request, null, 16, now, false);
            var difference = now >= request.TimeSigned ? now - request.TimeSigned : request.TimeSigned - now;
            var error = difference > Math.Min(request.Fudge, (ushort)300) ? (ushort)18
                : mac.Length < key.MinimumMacBytes ? (ushort)22 : (ushort)0;
            return new TsigTransaction(request, key.Copy(), error, now, key.AllowsPeer(peerAddress));
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed)
                return;
            disposed = true;
            foreach (var key in keys)
                key.Dispose();
        }
    }
}
