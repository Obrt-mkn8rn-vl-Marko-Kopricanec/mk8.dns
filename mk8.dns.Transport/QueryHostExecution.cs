using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Mk8.Dns.Transport;

// The caller owns the host and the listener's borrowed exchange. This scope
// joins both before returning, including failed startup and cancellation faults.
internal static class QueryHostExecution
{
    internal static async Task RunAsync(IHost host, Func<CancellationToken, Task>? listen)
    {
        using var cancellation = new CancellationTokenSource();
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var lifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();
        var registration = lifetime.ApplicationStopping.Register(() => stopped.TrySetResult());
        Task<Exception?>? serving = null;
        await ServiceExecution.RunAsync(RunAsync, CloseAsync,
            () => registration.DisposeAsync().AsTask()).ConfigureAwait(false);

        async Task RunAsync()
        {
            if (stopped.Task.IsCompleted) return;
            // Capture the terminal listener outcome before sibling cleanup can
            // request cancellation and reinterpret an unsolicited failure.
            if (listen is not null)
                serving = ServiceExecution.CaptureAsync(() => listen(cancellation.Token), cancellation.Token);
            if (serving?.IsCompleted == true || stopped.Task.IsCompleted) return;
            await host.StartAsync(CancellationToken.None).ConfigureAwait(false);
            if (serving is null)
                await stopped.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            else
                _ = await Task.WhenAny(serving.WaitAsync(CancellationToken.None), stopped.Task.WaitAsync(CancellationToken.None)).ConfigureAwait(false);
        }

        async Task CloseAsync()
        {
            // Initiate both before awaiting either. A held cancellation callback
            // must not prevent HTTP admission from beginning its own shutdown.
            var dispatch = ServiceExecution.CaptureAsync(cancellation.CancelAsync, CancellationToken.None);
            var stopping = ServiceExecution.CaptureAsync(() => host.StopAsync(CancellationToken.None), CancellationToken.None);
            ServiceExecution.ThrowFailures([
                await dispatch.ConfigureAwait(false),
                await stopping.ConfigureAwait(false),
                serving is null ? null : await serving.WaitAsync(CancellationToken.None).ConfigureAwait(false),
            ]);
        }
    }

}
