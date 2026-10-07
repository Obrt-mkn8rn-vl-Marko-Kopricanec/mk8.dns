using System.Buffers.Binary;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Infrastructure;

internal sealed class TsigTransaction : ITsigTransaction
{
    private readonly Lock sync = new();
    private readonly TsigRequest request;
    private readonly TsigKey? key;
    private readonly ulong now;
    private bool completed;
    private bool disposed;

    internal TsigTransaction(TsigRequest request, TsigKey? key, ushort error, ulong now, bool peerAllowed)
    {
        this.request = request;
        this.key = key;
        this.now = now;
        TsigError = error;
        PeerAllowed = peerAllowed;
        SignatureBytes = (ushort)TsigMessageCodec.GetRecordSize(request, key is null ? 0 : 32, error == 18 ? 6 : 0);
    }

    public ushort TsigError { get; }
    public ushort SignatureBytes { get; }
    public bool PeerAllowed { get; }

    public byte[] GetRequest()
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return request.GetMessage();
        }
    }

    public bool Authorizes(DnsName origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return TsigError == 0 && PeerAllowed && key?.Contains(origin) == true;
        }
    }

    public byte[] Complete(ReadOnlySpan<byte> response)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (completed)
                throw new InvalidOperationException("A TSIG query transaction has one response.");
            completed = true;
            var time = TsigError == 18 ? request.TimeSigned : now;
            var fudge = TsigError == 18 ? request.Fudge : Math.Min(request.Fudge, (ushort)300);
            byte[] other = [];
            if (TsigError == 18)
            {
                other = new byte[6];
                BinaryPrimitives.WriteUInt16BigEndian(other, (ushort)(now >> 32));
                BinaryPrimitives.WriteUInt32BigEndian(other.AsSpan(2), (uint)now);
            }
            var mac = key is null ? [] : key.Hash(TsigMessageCodec.CreateMacInput(response, request, request.GetMac(), time, fudge, TsigError, other));
            return TsigMessageCodec.AppendRecord(response, request, time, fudge, TsigError, mac, other);
        }
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed)
                return;
            disposed = true;
            key?.Dispose();
        }
    }
}
