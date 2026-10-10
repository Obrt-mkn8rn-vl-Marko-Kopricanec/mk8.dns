namespace Mk8.Dns.Engine.Recursive;

// One opt-in finite session. Source/store/provider/clock and external work remain
// caller-owned. Completion joins only this session's actual calls and cleanup.
public sealed partial class DnssecAnchorPoller : IAsyncDisposable
{
    private readonly Lock gate = new();
    private readonly DnssecAnchorRefresher refresher;
    private readonly DnssecAnchorPollingPolicy policy;
    private readonly TimeProvider time;
    private readonly DnssecResolutionClock clock;
    private readonly CancellationTokenSource cancellation;
    private readonly CancellationToken token;
    private readonly Task completion;
    private Task? cancellationTask;
    private TaskCompletionSource<bool>? pending;
    private Task? shutdown;
    private int attempts;
    private int applied;
    private int refused;
    private int busy;
    private bool closing;
    private bool finishing;
    private bool completed;
    private bool cancellationDisposed;

    public DnssecAnchorPoller(DnssecAnchorRefresher refresher, DnssecAnchorPollingPolicy policy, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(refresher);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(time);
        _ = refresher.Current; // Validate the borrowed acknowledged source before acquiring owned resources.
        this.refresher = refresher; this.policy = policy; this.time = time;
        clock = new DnssecResolutionClock(time);
        cancellation = new CancellationTokenSource(); token = cancellation.Token;
        completion = RunAsync();
    }

    public Task Completion => completion;
    public DnssecAnchorPollingStatistics Statistics
    {
        get { lock (gate) return new(attempts, applied, refused, busy, pending is not null, closing, completed); }
    }

    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            closing = true;
            if (!finishing)
            {
                cancellationTask ??= cancellation.CancelAsync();
                // Wake our timer wait independently of serial provider callback dispatch.
                pending?.TrySetResult(false);
            }
            shutdown ??= CloseAsync();
            return new ValueTask(shutdown);
        }
    }

    private async Task RunAsync()
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        try { await PollAsync().ConfigureAwait(false); }
        catch (Exception sourceError)
        {
            try { await FinishAsync().ConfigureAwait(false); }
            catch (Exception cleanupError) { throw new AggregateException(sourceError, cleanupError); }
            throw;
        }
        await FinishAsync().ConfigureAwait(false);
    }

    private async Task FinishAsync()
    {
        Task? callbacks;
        lock (gate) { finishing = true; callbacks = cancellationTask; }
        try { if (callbacks is not null) await callbacks.WaitAsync(CancellationToken.None).ConfigureAwait(false); }
        finally
        {
            DisposeCancellation();
            lock (gate) completed = true;
        }
    }

    private async Task CloseAsync()
    {
        try { await completion.WaitAsync(CancellationToken.None).ConfigureAwait(false); }
        finally { DisposeCancellation(); }
    }

    private void DisposeCancellation()
    {
        lock (gate)
        {
            if (cancellationDisposed) return;
            cancellation.Dispose(); cancellationDisposed = true;
        }
    }
}
