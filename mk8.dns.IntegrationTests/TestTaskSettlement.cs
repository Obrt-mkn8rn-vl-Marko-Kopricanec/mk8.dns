using System.Runtime.ExceptionServices;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

internal static class TestTaskSettlement
{
    internal static async Task AllAsync(params Func<Task>[] actions)
    {
        var observations = actions.Select(Record.ExceptionAsync).ToArray();
        var errors = (await Task.WhenAll(observations).ConfigureAwait(true)).OfType<Exception>().ToArray();
        if (errors.Length == 1) ExceptionDispatchInfo.Capture(errors[0]).Throw();
        if (errors.Length > 1) throw new AggregateException(errors);
    }

    internal static async Task ObserveAsync(Task operation, Func<Exception, bool>? expected = null)
    {
        var error = await Record.ExceptionAsync(() => operation.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        if (error is not null && !(expected?.Invoke(error) ?? false)) ExceptionDispatchInfo.Capture(error).Throw();
    }

    // Preserve the observation deadline, then own the actual operation through
    // settlement. The guard's completion is not the operation's completion.
    internal static async Task WaitAsync(Task operation, TimeSpan timeout)
    {
        var observer = await Record.ExceptionAsync(() => operation.WaitAsync(timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        var terminal = await Record.ExceptionAsync(() => operation.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        ThrowObservationErrors(operation, observer, terminal);
    }

    internal static async Task WaitAsync(Task operation, CancellationToken observationToken)
    {
        var observer = await Record.ExceptionAsync(async () =>
        {
            observationToken.ThrowIfCancellationRequested();
            await operation.WaitAsync(observationToken).ConfigureAwait(true);
        }).ConfigureAwait(true);
        var terminal = await Record.ExceptionAsync(() => operation.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        ThrowObservationErrors(operation, observer, terminal);
    }

    private static void ThrowObservationErrors(Task operation, Exception? observer, Exception? terminal)
    {
        var sameCancellation = operation.IsCanceled && observer is OperationCanceledException first
            && terminal is OperationCanceledException second && first.CancellationToken == second.CancellationToken;
        if (observer is not null && terminal is not null && !ReferenceEquals(observer, terminal) && !sameCancellation)
            throw new AggregateException(observer, terminal);
        if (observer is not null) ExceptionDispatchInfo.Capture(observer).Throw();
        if (terminal is not null) ExceptionDispatchInfo.Capture(terminal).Throw();
    }

    internal static async Task RunAsync(Func<Task> observe, Func<Task> settle)
    {
        var primary = await Record.ExceptionAsync(observe).ConfigureAwait(true);
        var cleanup = await Record.ExceptionAsync(settle).ConfigureAwait(true);
        if (primary is not null && cleanup is not null) throw new AggregateException(primary, cleanup);
        if (primary is not null) ExceptionDispatchInfo.Capture(primary).Throw();
        if (cleanup is not null) ExceptionDispatchInfo.Capture(cleanup).Throw();
    }
}
