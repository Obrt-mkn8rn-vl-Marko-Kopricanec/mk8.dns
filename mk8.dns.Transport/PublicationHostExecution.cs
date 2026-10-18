using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Mk8.Dns.Transport;

// The caller retires the hosts, control runtime and socket leases afterwards.
// StopAsync alone does not own a cancellation-ignoring publication operation.
internal static class PublicationHostExecution
{
    internal static async Task RunAsync(IHost application, IHost? publication,
        Action applicationStarted, Action publicationStarted, Func<CancellationToken, Task> publish)
    {
        using var cancellation = new CancellationTokenSource();
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var applicationLifetime = application.Services.GetRequiredService<IHostApplicationLifetime>();
        var applicationStop = applicationLifetime.ApplicationStopping.Register(() => stopped.TrySetResult());
        CancellationTokenRegistration publicationStop = default;
        Task<Exception?>? publishing = null;
        await ServiceExecution.RunAsync(RunAsync, CloseAsync,
            () => publicationStop.DisposeAsync().AsTask(),
            () => applicationStop.DisposeAsync().AsTask()).ConfigureAwait(false);

        async Task RunAsync()
        {
            if (publication is not null)
            {
                var lifetime = publication.Services.GetRequiredService<IHostApplicationLifetime>();
                publicationStop = lifetime.ApplicationStopping.Register(() => stopped.TrySetResult());
                await publication.StartAsync(CancellationToken.None).ConfigureAwait(false);
                publicationStarted();
            }
            if (stopped.Task.IsCompleted) return;
            await application.StartAsync(CancellationToken.None).ConfigureAwait(false);
            applicationStarted();
            if (stopped.Task.IsCompleted) return;
            publishing = ServiceExecution.CaptureAsync(() => publish(cancellation.Token), cancellation.Token);
            _ = await Task.WhenAny(stopped.Task.WaitAsync(CancellationToken.None), publishing.WaitAsync(CancellationToken.None)).ConfigureAwait(false);
            // A replica has no outbox loop. Successful completion does not end
            // serving; a failed publisher does, without waiting for another signal.
            if (publishing.IsCompleted && await publishing.WaitAsync(CancellationToken.None).ConfigureAwait(false) is not null) return;
            await stopped.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        }

        async Task CloseAsync()
        {
            var dispatch = ServiceExecution.CaptureAsync(cancellation.CancelAsync, CancellationToken.None);
            var applicationStopping = ServiceExecution.CaptureAsync(() => application.StopAsync(CancellationToken.None), CancellationToken.None);
            var publicationStopping = publication is null ? null
                : ServiceExecution.CaptureAsync(() => publication.StopAsync(CancellationToken.None), CancellationToken.None);
            ServiceExecution.ThrowFailures([
                await dispatch.ConfigureAwait(false),
                await applicationStopping.ConfigureAwait(false),
                publicationStopping is null ? null : await publicationStopping.ConfigureAwait(false),
                publishing is null ? null : await publishing.WaitAsync(CancellationToken.None).ConfigureAwait(false),
            ]);
        }
    }
}
