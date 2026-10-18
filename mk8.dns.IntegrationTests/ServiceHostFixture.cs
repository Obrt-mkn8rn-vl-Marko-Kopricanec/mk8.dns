using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Mk8.Dns.IntegrationTests;

internal sealed class ServiceHostFixture : IHost, IHostApplicationLifetime
{
    private readonly CancellationTokenSource stopping = new();
    private readonly ServiceProvider services;
    internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource StopEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Exception? StartFailure { get; init; }
    internal Exception? StopFailure { get; init; }
    internal Exception? DisposeFailure { get; init; }
    internal bool Disposed { get; private set; }

    internal ServiceHostFixture()
        => services = new ServiceCollection().AddSingleton<IHostApplicationLifetime>(this).BuildServiceProvider();

    public IServiceProvider Services => services;
    public CancellationToken ApplicationStarted => CancellationToken.None;
    public CancellationToken ApplicationStopping => stopping.Token;
    public CancellationToken ApplicationStopped => CancellationToken.None;

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Started.TrySetResult();
        return StartFailure is { } failure ? Task.FromException(failure) : Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        StopEntered.TrySetResult();
        return StopFailure is { } failure ? Task.FromException(failure) : Task.CompletedTask;
    }

    public void StopApplication() => stopping.Cancel();

    public void Dispose()
    {
        if (Disposed) return;
        Disposed = true;
        services.Dispose();
        stopping.Dispose();
    }

    internal Task CloseAsync()
    {
        Dispose();
        return DisposeFailure is { } failure ? Task.FromException(failure) : Task.CompletedTask;
    }
}
