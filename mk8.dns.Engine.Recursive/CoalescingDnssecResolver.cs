using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class CoalescingDnssecResolver : IAsyncDisposable
{
    private readonly Lock gate = new();
    private readonly CachingDnssecResolver source;
    private readonly DnssecWorkPolicy policy;
    private readonly TimeProvider time;
    private readonly DnssecResolutionClock clock;
    private readonly Dictionary<DnsQuestion, DnssecWorkFlight> pending = [];
    private readonly HashSet<DnssecWorkFlight> workers = [];
    private readonly TaskCompletionSource waitersDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Exception? cleanupFailure;
    private bool closing;
    private int waiters;
    private long started;
    private long coalesced;
    private long admissionRejections;

    public CoalescingDnssecResolver(CachingDnssecResolver source, DnssecWorkPolicy policy, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(policy);
        this.source = source; this.policy = policy; this.time = time ?? TimeProvider.System;
        clock = new DnssecResolutionClock(this.time);
    }

    public DnssecWorkStatistics Statistics
    {
        get { lock (gate) return new(workers.Count, waiters, started, coalesced, admissionRejections); }
    }

    public ValueTask<DnssecResolutionResult> ResolveDnssecAsync(DnsQuestion question, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (question.Name is null) throw new ArgumentException("An authenticated work question needs a name.", nameof(question));
        cancellationToken.ThrowIfCancellationRequested();
        DnssecWorkFlight flight;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            if (pending.TryGetValue(question, out var canceled) && canceled.Token.IsCancellationRequested) RemovePending(canceled);
            if (waiters == policy.MaximumWaiters || (!pending.ContainsKey(question) && workers.Count == policy.MaximumWorkers))
            {
                admissionRejections++; return ValueTask.FromResult(DnssecResolutionWork.Failure(question));
            }
            if (pending.TryGetValue(question, out var shared)) { flight = shared; coalesced++; }
            else
            {
                var created = CreateFlight(question);
                if (created is null)
                {
                    admissionRejections++; return ValueTask.FromResult(DnssecResolutionWork.Failure(question));
                }
                flight = created;
                pending.Add(question, flight); workers.Add(flight); started++;
                flight.Worker = RunAsync(flight);
            }
            waiters++; flight.Waiters++;
        }
        return AwaitAsync(flight, cancellationToken);
    }

    public void Clear()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            source.Clear();
            pending.Clear(); // Admitted work remains owned; new requests cannot join it.
        }
    }

    public ValueTask DisposeAsync()
    {
        DnssecWorkFlight[] active;
        lock (gate)
        {
            if (closing) return new ValueTask(disposed.Task);
            closing = true; pending.Clear(); active = [.. workers];
            foreach (var flight in active) flight.Abandoned = true;
            if (waiters == 0) waitersDrained.TrySetResult();
        }
        foreach (var flight in active) flight.Cancel();
        _ = FinishDisposalAsync(active);
        return new ValueTask(disposed.Task);
    }

    private async ValueTask<DnssecResolutionResult> AwaitAsync(DnssecWorkFlight flight, CancellationToken token)
    {
        try
        {
            var delivery = await flight.Completion.Task.WaitAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (closing || flight.Abandoned || flight.Token.IsCancellationRequested)
                    throw new OperationCanceledException("The authenticated work was abandoned.");
                return Deliver(delivery);
            }
        }
        finally
        {
            var cancel = false;
            lock (gate)
            {
                waiters--; flight.Waiters--;
                if (flight.Waiters == 0 && workers.Contains(flight))
                {
                    flight.Abandoned = true; RemovePending(flight); cancel = true;
                }
                if (closing && waiters == 0) waitersDrained.TrySetResult();
            }
            if (cancel) flight.Cancel();
        }
    }

    private void RemovePending(DnssecWorkFlight flight)
    {
        if (pending.TryGetValue(flight.Question, out var current) && ReferenceEquals(current, flight)) pending.Remove(flight.Question);
    }
}
