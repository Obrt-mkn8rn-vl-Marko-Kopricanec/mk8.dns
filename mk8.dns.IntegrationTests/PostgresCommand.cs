using System.Diagnostics;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

internal static class PostgresCommand
{
    internal static async Task RunAsync(ProcessStartInfo start, TimeSpan timeout,
        Action<Task, Task<string>, Task<string>>? observe = null)
    {
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the owned PostgreSQL development process.");
        var output = ReadAsync(process.StandardOutput);
        var errors = ReadAsync(process.StandardError);
        var exit = process.WaitForExitAsync(CancellationToken.None);
        using var deadline = new CancellationTokenSource(timeout);
        List<Exception> failures = [];
        var observerFailure = Record.Exception(() => observe?.Invoke(exit, output, errors));
        if (observerFailure is not null)
        {
            failures.Add(observerFailure);
        }
        else
        {
            var waiting = exit.WaitAsync(deadline.Token);
            await CaptureAsync(waiting, failures).ConfigureAwait(true);
        }
        if (!process.HasExited)
        {
            try { process.Kill(entireProcessTree: true); }
            catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                failures.Add(error);
            }
        }
        // Kill is a request. Keep process and dependent fixture roots owned through all three joins.
        await CaptureAsync(exit, failures).ConfigureAwait(true);
        await CaptureAsync(output, failures).ConfigureAwait(true);
        await CaptureAsync(errors, failures).ConfigureAwait(true);
        if (process.ExitCode != 0 && failures.Count == 0)
            failures.Add(new InvalidOperationException(await output.ConfigureAwait(true) + await errors.ConfigureAwait(true)));
        if (failures.Count == 1) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count > 1) throw new AggregateException(failures);
    }

    private static async Task<string> ReadAsync(StreamReader reader) => await reader.ReadToEndAsync().ConfigureAwait(true);

    private static async Task CaptureAsync(Task task, List<Exception> errors)
    {
        try { await task.WaitAsync(CancellationToken.None).ConfigureAwait(true); }
        catch (Exception error) when (task.IsFaulted || task.IsCanceled) { errors.Add(error); }
    }
}
