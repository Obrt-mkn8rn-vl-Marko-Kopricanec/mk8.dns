using Xunit;

namespace Mk8.Dns.IntegrationTests;

// Register a joinable owner before any downstream code can publish admission.
internal sealed class HandlerTaskOwners
{
    private readonly Lock gate = new();
    private readonly List<Task> owners = [];
    private Task? closing;

    internal Task InvokeAsync(Func<Task> next)
    {
        var published = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        var actual = published.Task.Unwrap();
        lock (gate)
        {
            if (closing is not null) return Task.FromException(new ObjectDisposedException(nameof(HandlerTaskOwners)));
            owners.Add(actual);
        }
        var error = Record.Exception(() => published.SetResult(next() ?? throw new InvalidOperationException("Downstream returned no task.")));
        if (error is not null) published.SetException(error);
        return actual;
    }

    internal Task SealAsync()
    {
        lock (gate) return closing ??= TestTaskSettlement.AllAsync([.. owners.Select(task => (Func<Task>)(() => ObserveOwnerAsync(task.WaitAsync(CancellationToken.None))))]);
    }
    private static async Task ObserveOwnerAsync(Task task)
    {
        var error = await Record.ExceptionAsync(() => task.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        if (task.Exception is { InnerExceptions.Count: > 1 } aggregate) throw aggregate;
        if (error is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
    }
}
