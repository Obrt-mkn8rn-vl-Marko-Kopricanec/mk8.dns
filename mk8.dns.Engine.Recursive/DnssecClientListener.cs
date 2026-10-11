using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Mk8.Dns.Engine.Recursive;

// Owns only its sockets, sessions and cancellation dispatch. The caller owns
// the processor and any independent epoch/provider work detached by cancellation.
public sealed partial class DnssecClientListener : IAsyncDisposable
{
    private readonly Lock gate = new();
    [SuppressMessage("Usage", "CA2213:Disposable fields should be disposed", Justification = "The processor is explicitly borrowed; listener closure joins its admitted calls but must not close other consumers or its independent epoch drain.")]
    private readonly DnssecClientRequestProcessor processor;
    private readonly IPEndPoint endpoint;
    private readonly int udpWorkers;
    private readonly int maximumTcpConnections;
    private readonly int maximumTcpMessages;
    private readonly TaskCompletionSource<IPEndPoint> bound = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CancellationTokenSource? cancellation;
    private Task? cancellationDispatch;
    private Task? execution;
    private Task? disposal;
    private bool closing;
    private bool finishing;
    private int activeTcp;

    public DnssecClientListener(DnssecClientRequestProcessor processor, IPEndPoint endpoint,
        int udpWorkers = 4, int maximumTcpConnections = 16, int maximumTcpMessages = 16)
    {
        ArgumentNullException.ThrowIfNull(processor);
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!processor.RequiresCompleteTcpAnswers)
            throw new ArgumentException("Native sessions require the explicit complete-TCP processor.", nameof(processor));
        if (udpWorkers is < 1 or > 16 || maximumTcpConnections is < 1 or > 64 || maximumTcpMessages is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(udpWorkers), "Invalid native listener admission bounds.");
        if (endpoint.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            || endpoint.Address.IsIPv4MappedToIPv6 || endpoint.Address.IsIPv6Multicast
            || endpoint.Address.GetAddressBytes().AsSpan().IndexOfAnyExcept((byte)0) < 0
            || IsMulticastOrBroadcast(endpoint.Address))
        {
            throw new ArgumentException("Supply a specific canonical IPv4 or IPv6 bind address.", nameof(endpoint));
        }
        this.processor = processor; this.endpoint = Copy(endpoint);
        this.udpWorkers = udpWorkers; this.maximumTcpConnections = maximumTcpConnections;
        this.maximumTcpMessages = maximumTcpMessages;
    }

    // Admission observation, not readiness or a hard capacity/progress bound.
    public int ActiveTcpConnections => Volatile.Read(ref activeTcp);

    public Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            if (execution is not null) throw new InvalidOperationException("A native listener can run only once.");
            cancellation = new CancellationTokenSource();
            try { execution = ExecuteAsync(cancellationToken); }
            catch { cancellation.Dispose(); cancellation = null; throw; }
            return execution;
        }
    }

    // Binding is a historical observation, not service readiness. Port zero
    // selects one actual port shared by both protocols; failed partial binds close.
    public async Task<IPEndPoint> WaitForBoundAsync(CancellationToken cancellationToken)
        => Copy(await bound.Task.WaitAsync(cancellationToken).ConfigureAwait(false));

    public ValueTask DisposeAsync()
    {
        RequestStop();
        lock (gate) return new ValueTask(disposal ??= FinishDisposalAsync());
    }

    private void RequestStop()
    {
        lock (gate)
        {
            closing = true;
            if (finishing) return;
            if (cancellation is null) bound.TrySetCanceled(new CancellationToken(canceled: true));
            else cancellationDispatch ??= cancellation.CancelAsync();
        }
    }

    // Protocol address classifications, never deployment subnet assignments.
    private static bool IsMulticastOrBroadcast(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 && (bytes[0] is >= 224 and <= 239 || bytes.AsSpan().IndexOfAnyExcept((byte)255) < 0);
    }

    private static IPEndPoint Copy(IPEndPoint value)
        => new(value.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPAddress(value.Address.GetAddressBytes(), value.Address.ScopeId)
            : new IPAddress(value.Address.GetAddressBytes()), value.Port);
}
