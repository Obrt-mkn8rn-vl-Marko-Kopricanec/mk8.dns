using Mk8.Dns.Wire;

namespace Mk8.Dns.Engine.Recursive;

// Owns admitted packet requests only. The caller owns the transport's true peer
// identity and resolver lifetime, including independent coalesced worker drains.
public sealed partial class DnssecClientRequestProcessor : IAsyncDisposable
{
    private readonly Lock gate = new();
    private readonly DnssecTrustEpochResolver source;
    private readonly DnssecClientAccessPolicy policy;
    private readonly int maximumRequests;
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int activeRequests;
    private bool closing;

    public DnssecClientRequestProcessor(DnssecTrustEpochResolver source, DnssecClientAccessPolicy policy, int maximumRequests = 64)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(policy);
        if (!source.CapturesClientProof)
            throw new ArgumentException("The client processor requires an explicit proof-aware epoch resolver.", nameof(source));
        if (maximumRequests is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(maximumRequests));
        this.source = source; this.policy = policy; this.maximumRequests = maximumRequests;
    }

    public int ActiveRequests { get { lock (gate) return activeRequests; } }

    public ValueTask<DnssecClientReply> ProcessAsync(ReadOnlyMemory<byte> request, ReadOnlyMemory<byte> peerAddress,
        bool tcp, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            if (peerAddress.Length is not (4 or 16) || !policy.Allows(peerAddress.ToArray()))
                return ValueTask.FromResult(new DnssecClientReply(DnssecClientReplyOutcome.Denied, []));
            if (request.Length > DnsMessageCodec.MaximumMessageBytes)
                return ValueTask.FromResult(new DnssecClientReply(DnssecClientReplyOutcome.Malformed, []));
            if (activeRequests == maximumRequests)
                return ValueTask.FromResult(new DnssecClientReply(DnssecClientReplyOutcome.Overloaded, []));
            activeRequests++;
            byte[] packet;
            try { packet = request.ToArray(); }
            catch { Release(); throw; }
            return ExecuteAsync(packet, tcp, cancellationToken);
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            closing = true;
            if (activeRequests == 0) drained.TrySetResult();
            return new ValueTask(drained.Task);
        }
    }

    private void Release()
    {
        lock (gate)
        {
            activeRequests--;
            if (closing && activeRequests == 0) drained.TrySetResult();
        }
    }

    private DnssecClientReply Deliver(DnssecClientReply reply)
    {
        lock (gate) return closing ? new DnssecClientReply(DnssecClientReplyOutcome.Closed, []) : reply;
    }
}
