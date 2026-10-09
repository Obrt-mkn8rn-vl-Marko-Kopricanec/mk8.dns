using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

internal sealed class DnssecWorkFlight : IAsyncDisposable
{
    private readonly Lock gate = new();
    private readonly CancellationTokenSource cancellation = new();
    private readonly ITimer timer;
    private Task? cancellationTask;
    private bool finishing;

    internal DnssecWorkFlight(DnsQuestion question, TimeProvider time, TimeSpan timeout)
    {
        Question = question; Token = cancellation.Token;
        try { timer = time.CreateTimer(static state => ((DnssecWorkFlight)state!).Cancel(), this, timeout, Timeout.InfiniteTimeSpan); }
        catch { cancellation.Dispose(); throw; }
    }

    internal DnsQuestion Question { get; }
    internal CancellationToken Token { get; }
    internal TaskCompletionSource<Delivery> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task Worker { get; set; } = Task.CompletedTask;
    internal int Waiters { get; set; }
    internal bool Abandoned { get; set; }

    internal void Cancel()
    {
        lock (gate)
        {
            if (finishing) return;
            cancellationTask ??= cancellation.CancelAsync();
            // Provider callbacks may hold the serial dispatcher; waiter signaling is independent.
            Completion.TrySetCanceled(Token);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await timer.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            Task? callbacks;
            lock (gate) { finishing = true; callbacks = cancellationTask; }
            try { if (callbacks is not null) await callbacks.WaitAsync(CancellationToken.None).ConfigureAwait(false); }
            finally { cancellation.Dispose(); }
        }
    }

    internal sealed record Delivery(DnssecResolutionResult Result, long Received);
}
