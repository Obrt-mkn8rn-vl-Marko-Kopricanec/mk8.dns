using System.Runtime.ExceptionServices;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.Application;

// This finite executable scope closes its host and poller. The refresher, store,
// provider and clock remain borrowed and are closed later by startup's owner.
internal static class RecursiveRefreshExecution
{
    internal static async Task RunAsync(DnssecClientHost host, DnssecAnchorRefresher refresher,
        DnssecAnchorPollingPolicy policy, TimeProvider time, CancellationToken token)
    {
        var serving = CaptureAsync(RunHostAsync(host, token));
        var refreshing = CaptureAsync(RefreshAsync(host, refresher, policy, time, serving, token));
        _ = await Task.WhenAny(serving, refreshing).ConfigureAwait(false);
        var hostClosure = CaptureAsync(CloseAsync(host));
        List<Exception> failures = [];
        await CollectAsync([serving, refreshing, hostClosure], failures).ConfigureAwait(false);
        ThrowFailures(failures);
    }

    private static async Task RefreshAsync(DnssecClientHost host, DnssecAnchorRefresher refresher,
        DnssecAnchorPollingPolicy policy, TimeProvider time, Task serving, CancellationToken token)
    {
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var registration = token.Register(() => stopped.TrySetResult()).ConfigureAwait(false);
        var poller = DnssecAnchorPoller.CreateWithAuthenticatedTiming(refresher, policy, time);
        await using var lifetime = poller.ConfigureAwait(false);
        try
        {
            // A finite successful polling cap ends serving, too. A source fault
            // cannot leave a native listener running on stale refresh authority.
            _ = await Task.WhenAny(serving.WaitAsync(CancellationToken.None), poller.Completion, stopped.Task).ConfigureAwait(false);
        }
        finally
        {
            // Initiate BOTH closures before joining either: a held refresh provider
            // must not delay native admission stop, or vice versa. Captures retain
            // each actual terminal outcome before sibling teardown can alter tokens.
            var hostClosure = CaptureAsync(CloseAsync(host));
            var pollerClosure = CaptureAsync(ClosePollerAsync(poller));
            List<Exception> failures = [];
            await CollectAsync([CaptureAsync(poller.Completion), hostClosure, pollerClosure], failures).ConfigureAwait(false);
            ThrowFailures(failures);
        }
    }

    private static async Task RunHostAsync(DnssecClientHost host, CancellationToken token)
        => await host.RunAsync(token).ConfigureAwait(false);

    private static async Task CloseAsync(DnssecClientHost host)
        => await host.DisposeAsync().ConfigureAwait(false);

    private static async Task ClosePollerAsync(DnssecAnchorPoller poller)
        => await poller.DisposeAsync().ConfigureAwait(false);

    private static async Task CollectAsync(IEnumerable<Task<Exception?>?> tasks, List<Exception> failures)
    {
        foreach (var task in tasks)
        {
            if (task is not null && await task.WaitAsync(CancellationToken.None).ConfigureAwait(false) is { } error) failures.Add(error);
        }
    }

    private static void ThrowFailures(List<Exception> failures)
    {
        if (failures.Count == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count > 1) throw new AggregateException(failures);
    }

    private static async Task<Exception?> CaptureAsync(Task task)
    {
        try { await task.WaitAsync(CancellationToken.None).ConfigureAwait(false); return null; }
        catch (Exception error) when (task.IsFaulted || task.IsCanceled)
        {
            if (task.Exception is { InnerExceptions.Count: 1 } single) return single.InnerExceptions[0];
            return task.Exception ?? error;
        }
    }
}
