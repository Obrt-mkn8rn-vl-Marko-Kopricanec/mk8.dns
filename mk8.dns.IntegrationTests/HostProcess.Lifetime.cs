using System.Runtime.ExceptionServices;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

internal sealed partial class HostProcess
{
    private readonly Lock closeGate = new();
    private Task? close;

    internal string InstallationDirectory => Path.GetDirectoryName(installation.AssemblyPath)
        ?? throw new InvalidDataException("FixtureInstallationDirectoryMissing");
    internal (Task Exit, Task<string> Output, Task<string> Errors) Operations => (exit, output, errors);

    public ValueTask DisposeAsync()
    {
        lock (closeGate) return new ValueTask(close ??= CloseWithDeadlineAsync());
    }

    // A test-only observation token can fail the guard without abandoning the
    // independently owned retirement. Repeated disposal keeps that first result.
    internal Task CloseAsync(CancellationToken observationToken)
    {
        lock (closeGate) return close ??= TestTaskSettlement.WaitAsync(RetireAsync(), observationToken);
    }

    private async Task CloseWithDeadlineAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await TestTaskSettlement.WaitAsync(RetireAsync(), timeout.Token).ConfigureAwait(true);
    }

    private void RequestKill()
    {
        if (!process.HasExited) process.Kill(entireProcessTree: true);
    }

    private async Task RetireAsync()
    {
        List<Exception> failures = [];
        Add(Record.Exception(RequestKill));
        Add(await Record.ExceptionAsync(() => TestTaskSettlement.AllAsync(
            () => exit.WaitAsync(CancellationToken.None),
            () => output.WaitAsync(CancellationToken.None),
            () => errors.WaitAsync(CancellationToken.None))).ConfigureAwait(true));

        // A kill request or failed exit observer is not evidence of actual exit.
        // Keep dependent files/handles if actual exit was not established.
        if (exit.IsCompletedSuccessfully)
        {
            Add(await Record.ExceptionAsync(() => SaveDiagnosticsAsync(CancellationToken.None)).ConfigureAwait(true));
            var installationClosing = CloseInstallationAsync();
            Add(await Record.ExceptionAsync(() => installationClosing.WaitAsync(CancellationToken.None)).ConfigureAwait(true));
            Add(Record.Exception(process.Dispose));
        }
        if (failures.Count == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count > 1) throw new AggregateException(failures);

        void Add(Exception? failure)
        {
            if (failure is not null) failures.Add(failure);
        }
    }

    private async Task CloseInstallationAsync()
    {
        await Task.CompletedTask.ConfigureAwait(true);
        installation.Dispose();
    }
}
