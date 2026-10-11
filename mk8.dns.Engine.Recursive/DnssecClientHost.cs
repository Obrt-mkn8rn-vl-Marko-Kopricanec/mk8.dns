using System.Net;
using System.Runtime.ExceptionServices;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

// Owns the explicitly constructed listener, processor and proof-aware epoch.
// Refresher/store, upstream, verifier and both clocks remain caller-owned.
// This composition does not provision anchors, schedule refreshes or install a host.
public sealed class DnssecClientHost : IAsyncDisposable
{
    private readonly Lock gate = new();
    private DnssecTrustEpochResolver? epoch;
    private DnssecClientRequestProcessor? processor;
    private DnssecClientListener? listener;
    private Task? execution;
    private Task? cleanup;
    private Task? disposal;
    private bool closing;

    private DnssecClientHost() { }

    public static async ValueTask<DnssecClientHost> CreateAsync(DnssecAnchorRefresher refresher,
        IDnssecUpstream upstream, IDnssecSignatureVerifier verifier, IEnumerable<DnsServerEndpoint> roots,
        DnssecTrustEpochPolicy epochPolicy, DnssecClientAccessPolicy access, IPEndPoint endpoint,
        DnssecWorkPolicy workPolicy, TimeProvider time, ushort authorityPort = 53,
        int maximumRequests = 64, int udpWorkers = 4, int maximumTcpConnections = 16, int maximumTcpMessages = 16)
    {
        // Construction creates no listeners or provider work. The epoch validates
        // its caller inputs; subsequent failure still drains every acquired owner.
        var host = new DnssecClientHost();
        try
        {
            host.epoch = DnssecTrustEpochResolver.CreateWithClientProofAndCoalescing(refresher, upstream, verifier,
                roots, epochPolicy, workPolicy, time, authorityPort);
            host.processor = DnssecClientRequestProcessor.CreateWithCompleteTcpAnswers(host.epoch, access, maximumRequests);
            host.listener = new DnssecClientListener(host.processor, endpoint, udpWorkers, maximumTcpConnections, maximumTcpMessages);
            return host;
        }
        catch (Exception error)
        {
            var cleanupError = await CaptureAsync(host.DisposeAsync().AsTask()).ConfigureAwait(false);
            if (cleanupError is not null) throw new AggregateException(error, cleanupError);
            throw;
        }
    }

    public int ActiveRequests => processor?.ActiveRequests ?? 0;
    public int ActiveWorkers => epoch?.ActiveWorkers ?? 0;
    public int ActiveTcpConnections => listener?.ActiveTcpConnections ?? 0;

    public Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            if (execution is not null) throw new InvalidOperationException("A native client host can run only once.");
            execution = ExecuteAsync(RequireListener().RunAsync(cancellationToken));
            return execution;
        }
    }

    // The cloned endpoint is a historical bind observation, not readiness.
    public Task<IPEndPoint> WaitForBoundAsync(CancellationToken cancellationToken)
        => RequireListener().WaitForBoundAsync(cancellationToken);

    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            var closingTask = BeginCleanupAsync();
            disposal ??= execution is null ? closingTask : Task.WhenAll(execution, closingTask);
            return new ValueTask(disposal);
        }
    }

    private async Task ExecuteAsync(Task running)
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        var failure = await CaptureAsync(running).WaitAsync(CancellationToken.None).ConfigureAwait(false);
        Task closingTask;
        lock (gate) closingTask = BeginCleanupAsync();
        var cleanupFailure = await CaptureAsync(closingTask).ConfigureAwait(false);
        ThrowFailure(failure is null ? cleanupFailure : cleanupFailure is null ? failure : new AggregateException(failure, cleanupFailure));
    }

    private DnssecClientListener RequireListener()
        => listener ?? throw new InvalidOperationException("Host construction has not completed.");

    private static async Task<Exception?> CaptureAsync(Task task)
    {
        try { await task.WaitAsync(CancellationToken.None).ConfigureAwait(false); return null; }
        catch (Exception error) when (task.IsFaulted || task.IsCanceled)
        {
            if (task.Exception is { InnerExceptions.Count: 1 } single) return single.InnerExceptions[0];
            return task.Exception ?? error;
        }
    }

    private static void ThrowFailure(Exception? error)
    {
        if (error is not null) ExceptionDispatchInfo.Capture(error).Throw();
    }

    private Task BeginCleanupAsync()
    {
        closing = true;
        // Stop native admission at this boundary. Its disposal body yields before
        // joining calls, so borrowed work does not run under the host gate.
        return cleanup ??= CleanupAsync(listener is null ? Task.CompletedTask : DisposeResourceAsync(listener));
    }

    private static async Task DisposeResourceAsync(IAsyncDisposable resource)
        => await resource.DisposeAsync().ConfigureAwait(false);

    private async Task CleanupAsync(Task listenerClosure)
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        List<Exception> failures = [];
        var listenerError = await CaptureAsync(listenerClosure).WaitAsync(CancellationToken.None).ConfigureAwait(false);
        if (listenerError is not null) failures.Add(listenerError);
        // Listener stop first joins its admitted calls; processor closure follows.
        // Epoch closure then joins workers detached by those canceled calls. A
        // prior failure cannot skip any owner, and ignored work may stall forever.
        foreach (var resource in new IAsyncDisposable?[] { processor, epoch })
        {
            if (resource is null) continue;
            // Capture actual asynchronous completion; cancellation is retained,
            // not normalized using a later teardown request.
            var pending = DisposeResourceAsync(resource);
            var error = await CaptureAsync(pending).ConfigureAwait(false);
            if (error is not null) failures.Add(error);
        }
        if (failures.Count == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count > 1) throw new AggregateException(failures);
    }
}
