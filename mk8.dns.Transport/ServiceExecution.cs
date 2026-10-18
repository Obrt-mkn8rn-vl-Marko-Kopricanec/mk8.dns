using System.Runtime.ExceptionServices;

namespace Mk8.Dns.Transport;

// Executable composition owns the operations passed here. A failed stop must
// still settle before its borrowers can retire, and must not skip another stop.
internal static class ServiceExecution
{
    internal static async Task<Exception?> CaptureAsync(Func<Task> action, CancellationToken expectedCancellation)
    {
        Task? actual = null;
        try
        {
            actual = action();
            await actual.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            return null;
        }
        catch (Exception error) when (actual is null or { IsFaulted: true } or { IsCanceled: true })
        {
            if (actual?.IsCanceled == true && expectedCancellation.IsCancellationRequested
                && error is OperationCanceledException canceled && canceled.CancellationToken == expectedCancellation)
            {
                return null;
            }
            if (actual?.Exception is { InnerExceptions.Count: 1 } single) return single.InnerExceptions[0];
            return actual?.Exception ?? error;
        }
    }

    internal static async Task RunAsync(Func<Task> body, params Func<Task>[] cleanup)
    {
        List<Exception?> failures = [await CaptureAsync(body, CancellationToken.None).ConfigureAwait(false)];
        foreach (var close in cleanup)
            failures.Add(await CaptureAsync(close, CancellationToken.None).ConfigureAwait(false));
        ThrowFailures(failures);
    }

    internal static void ThrowFailures(IEnumerable<Exception?> outcomes)
    {
        var failures = outcomes.OfType<Exception>().ToArray();
        if (failures.Length == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Length > 1) throw new AggregateException(failures);
    }
}
