using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

internal sealed class RecursiveCacheFlight : IAsyncDisposable
{
    private readonly Lock cancellationGate = new();
    private readonly CancellationTokenSource cancellation = new();
    private readonly CancellationTokenRegistration canceled;
    private readonly ITimer deadline;
    private Task? cancellationTask;
    private bool finishing;

    internal RecursiveCacheFlight(DnsQuestion question, long generation, TimeProvider time, TimeSpan timeout)
    {
        Question = question;
        Generation = generation;
        Token = cancellation.Token;
        canceled = Token.Register(() => Completion.TrySetCanceled(Token));
        try
        {
            // Cancellation callbacks run asynchronously and remain owned until disposal joins them.
            deadline = time.CreateTimer(static state => ((RecursiveCacheFlight)state!).Cancel(), this, timeout, Timeout.InfiniteTimeSpan);
        }
        catch
        {
            canceled.Dispose();
            cancellation.Dispose();
            throw;
        }
    }

    internal DnsQuestion Question { get; }
    internal long Generation { get; }
    internal CancellationToken Token { get; }
    internal TaskCompletionSource<RecursiveCacheResult> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task Worker { get; set; } = Task.CompletedTask;
    internal int Waiters { get; set; }
    internal bool Abandoned { get; set; }

    internal void Cancel()
    {
        lock (cancellationGate)
        {
            if (!finishing)
                cancellationTask ??= cancellation.CancelAsync();
        }
    }

    public async ValueTask DisposeAsync()
    {
        Task? pending;
        lock (cancellationGate)
        {
            finishing = true;
            pending = cancellationTask;
        }
        try
        {
            await deadline.DisposeAsync().ConfigureAwait(false);
            if (pending is not null)
                await pending.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            await canceled.DisposeAsync().ConfigureAwait(false);
            cancellation.Dispose();
        }
    }
}
