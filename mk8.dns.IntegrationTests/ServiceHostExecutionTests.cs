using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ServiceHostExecutionTests
{
    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(5);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QueryStopBeginsDuringHeldCallbackAndJoinsListenerBeforeHostDisposal(bool failListener)
    {
        var callbackFailure = new IOException("Controlled cancellation callback failure.");
        var stopFailure = new InvalidOperationException("Controlled host stop failure.");
        var listenerFailure = new InvalidDataException("Controlled listener failure.");
        var disposeFailure = new IOException("Controlled host disposal failure.");
        using var host = new ServiceHostFixture { StopFailure = stopFailure, DisposeFailure = disposeFailure };
        using var callbackRelease = new ManualResetEventSlim();
        var callbackEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var listenerRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = ServiceExecution.RunAsync(async () => await QueryHostExecution.RunAsync(host, ListenAsync).ConfigureAwait(true),
            () => host.CloseAsync());
        var expected = failListener ? new Exception[] { callbackFailure, stopFailure, listenerFailure, disposeFailure }
            : [callbackFailure, stopFailure, disposeFailure];
        await TestTaskSettlement.RunAsync(async () =>
        {
            await host.Started.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            host.StopApplication();
            await callbackEntered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await host.StopEntered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.False(running.IsCompleted);
            Assert.False(host.Disposed);
            callbackRelease.Set();
            Assert.False(running.IsCompleted);
            listenerRelease.TrySetResult();
            var error = await Record.ExceptionAsync(() => running.WaitAsync(Guard, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            AssertFailures(error, expected);
            Assert.True(host.Disposed);
        }, async () =>
        {
            callbackRelease.Set();
            listenerRelease.TrySetResult();
            if (!host.Disposed) host.StopApplication();
            await TestTaskSettlement.ObserveAsync(running.WaitAsync(CancellationToken.None), error => OnlyExpected(error, expected)).ConfigureAwait(true);
        }).ConfigureAwait(true);

        async Task ListenAsync(CancellationToken token)
        {
            var registration = token.Register(() =>
            {
                callbackEntered.TrySetResult();
                if (!callbackRelease.Wait(Guard, CancellationToken.None)) throw new TimeoutException("Callback release observation failed.");
                throw callbackFailure;
            });
            await using var callback = registration.ConfigureAwait(true);
            await listenerRelease.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            if (failListener) throw listenerFailure;
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnsolicitedListenerFailureSurvivesLaterShutdownCancellation(bool canceled)
    {
        using var host = new ServiceHostFixture();
        Exception failure = canceled ? new OperationCanceledException("Unsolicited listener cancellation.")
            : new IOException("Controlled binding refusal.");
        var running = ServiceExecution.RunAsync(async () => await QueryHostExecution.RunAsync(host, ListenAsync).ConfigureAwait(true),
            () => host.CloseAsync());
        var error = await Record.ExceptionAsync(() => running.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        Assert.Same(failure, error);
        Assert.False(host.Started.Task.IsCompleted);
        Assert.True(host.StopEntered.Task.IsCompleted);
        Assert.True(host.Disposed);

        async Task ListenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            await Task.CompletedTask.ConfigureAwait(true);
            throw failure;
        }
    }

    [Fact]
    public async Task FailedHostStartStillOwnsAnAdmittedListenerAndEveryCleanupError()
    {
        var startup = new IOException("Controlled HTTP startup failure.");
        var stopping = new IOException("Controlled HTTP shutdown failure.");
        var disposal = new IOException("Controlled HTTP disposal failure.");
        using var host = new ServiceHostFixture { StartFailure = startup, StopFailure = stopping, DisposeFailure = disposal };
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = ServiceExecution.RunAsync(async () => await QueryHostExecution.RunAsync(host,
            _ => release.Task.WaitAsync(CancellationToken.None)).ConfigureAwait(true),
            () => host.CloseAsync());
        Exception[] expected = [startup, stopping, disposal];
        await TestTaskSettlement.RunAsync(async () =>
        {
            await host.StopEntered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.False(running.IsCompleted);
            Assert.False(host.Disposed);
            release.TrySetResult();
            var error = await Record.ExceptionAsync(() => running.WaitAsync(Guard, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            AssertFailures(error, expected);
            Assert.True(host.Disposed);
        }, async () =>
        {
            release.TrySetResult();
            await TestTaskSettlement.ObserveAsync(running.WaitAsync(CancellationToken.None), error => OnlyExpected(error, expected)).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }

    [Fact]
    public async Task SynchronousFailureAndEveryFaultOfAnActualCleanupTaskAreRetained()
    {
        var original = new IOException("Original body failure.");
        var first = new IOException("First cleanup failure.");
        var second = new InvalidOperationException("Second cleanup failure.");
        var laterOwner = false;
        var error = await Record.ExceptionAsync(() => ServiceExecution.RunAsync(
            () => throw original,
            () => Task.WhenAll(Task.FromException(first), Task.FromException(second)),
            () => { laterOwner = true; return Task.CompletedTask; })).ConfigureAwait(true);
        AssertFailures(error, original, first, second);
        Assert.True(laterOwner);
    }

    internal static bool OnlyExpected(Exception error, IReadOnlyCollection<Exception> expected)
        => error is AggregateException aggregate
            ? aggregate.Flatten().InnerExceptions.All(leaf => expected.Any(candidate => ReferenceEquals(candidate, leaf)))
            : expected.Any(candidate => ReferenceEquals(candidate, error));

    internal static void AssertFailures(Exception? error, params Exception[] expected)
    {
        var actual = Assert.IsType<AggregateException>(error).Flatten().InnerExceptions;
        Assert.Equal(expected.Length, actual.Count);
        Assert.All(expected, failure => Assert.Contains(actual, observed => ReferenceEquals(failure, observed)));
    }
}
