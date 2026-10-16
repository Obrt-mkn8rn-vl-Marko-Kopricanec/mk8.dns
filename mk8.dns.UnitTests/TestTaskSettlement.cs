using System.Runtime.ExceptionServices;
using Xunit;

namespace Mk8.Dns.UnitTests;

internal static class TestTaskSettlement
{
    internal static async Task CaptureAsync(Task actual, List<Exception> failures)
    {
        var error = await Record.ExceptionAsync(() => actual.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        if (actual.Exception is { InnerExceptions.Count: > 1 } aggregate) failures.Add(aggregate);
        else if (error is not null) failures.Add(error);
    }

    internal static void ThrowFailures(List<Exception> failures)
    {
        if (failures.Count == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count > 1) throw new AggregateException(failures);
    }

    internal static async Task InOrderAsync(params Func<Task>[] actions)
    {
        List<Exception> errors = [];
        foreach (var action in actions)
        {
            var error = await Record.ExceptionAsync(action).ConfigureAwait(true);
            if (error is not null) errors.Add(error);
        }
        if (errors.Count == 1) ExceptionDispatchInfo.Capture(errors[0]).Throw();
        if (errors.Count > 1) throw new AggregateException(errors);
    }

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
    internal static async Task WaitAsync(Task operation, TimeSpan timeout, Func<Exception, bool>? expected = null)
    {
        var observer = await Record.ExceptionAsync(() => operation.WaitAsync(timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        var terminal = await Record.ExceptionAsync(() => operation.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        var sameCancellation = operation.IsCanceled && observer is OperationCanceledException first
            && terminal is OperationCanceledException second && first.CancellationToken == second.CancellationToken;
        if (terminal is not null && expected?.Invoke(terminal) == true)
        {
            if (ReferenceEquals(observer, terminal) || sameCancellation) observer = null;
            terminal = null;
        }
        if (observer is not null && terminal is not null && !ReferenceEquals(observer, terminal) && !sameCancellation)
            throw new AggregateException(observer, terminal);
        if (observer is not null) ExceptionDispatchInfo.Capture(observer).Throw();
        if (terminal is not null) ExceptionDispatchInfo.Capture(terminal).Throw();
    }

    internal static async Task CancelReleaseAndJoinAsync(CancellationTokenSource caller, Action release, Task operation, TimeSpan timeout)
    {
        var dispatch = caller.CancelAsync();
        await RunAsync(() => { release(); return Task.CompletedTask; },
            () => AllAsync(() => dispatch.WaitAsync(CancellationToken.None),
                () => RunAsync(
                    () => Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(timeout, TimeProvider.System, CancellationToken.None)),
                    () => ObserveAsync(operation.WaitAsync(CancellationToken.None), error => error is OperationCanceledException)))).ConfigureAwait(true);
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
