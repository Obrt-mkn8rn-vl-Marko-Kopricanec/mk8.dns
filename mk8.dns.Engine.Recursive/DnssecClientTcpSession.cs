using System.Diagnostics.CodeAnalysis;

namespace Mk8.Dns.Engine.Recursive;

// One finite serial session on an exclusively caller-owned stream. The caller
// supplies the true peer, deadline/cancellation and independent processor drain.
public sealed partial class DnssecClientTcpSession : IAsyncDisposable
{
    private readonly Lock gate = new();
    [SuppressMessage("Usage", "CA2213:Disposable fields should be disposed", Justification = "The caller owns this processor and its independent drain. Session closure joins only admitted calls; disposing the processor would close other sessions.")]
    private readonly DnssecClientRequestProcessor processor;
    [SuppressMessage("Usage", "CA2213:Disposable fields should be disposed", Justification = "This stream is explicitly borrowed. The caller owns connection teardown; session closure joins admitted read/write/flush operations without disposing the stream.")]
    private readonly Stream stream;
    private readonly byte[] peer;
    private readonly int maximumMessages;
    private Task<DnssecClientTcpSessionResult>? execution;
    private bool closing;

    public DnssecClientTcpSession(DnssecClientRequestProcessor processor, Stream stream,
        ReadOnlyMemory<byte> peerAddress, int maximumMessages = 16)
    {
        ArgumentNullException.ThrowIfNull(processor);
        ArgumentNullException.ThrowIfNull(stream);
        if (!processor.RequiresCompleteTcpAnswers)
            throw new ArgumentException("The stream session requires the explicit complete-TCP processor.", nameof(processor));
        if (maximumMessages is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(maximumMessages));
        if (peerAddress.Length is not (4 or 16)) throw new ArgumentException("Supply a complete peer address.", nameof(peerAddress));
        if (!stream.CanRead || !stream.CanWrite) throw new ArgumentException("Supply a readable and writable stream.", nameof(stream));
        this.processor = processor; this.stream = stream; peer = peerAddress.ToArray(); this.maximumMessages = maximumMessages;
    }

    public ValueTask<DnssecClientTcpSessionResult> RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            if (execution is not null) throw new InvalidOperationException("A TCP session can run only once.");
            execution = ExecuteAsync(cancellationToken);
            return new ValueTask<DnssecClientTcpSessionResult>(execution);
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            closing = true;
            // Closing fences the NEXT frame, never cancels or releases admitted
            // read/provider/write/flush work. Faults remain on this shared task.
            return execution is null ? ValueTask.CompletedTask : new ValueTask(execution);
        }
    }

    private bool TryBeginFrame()
    {
        lock (gate) return !closing;
    }
}
