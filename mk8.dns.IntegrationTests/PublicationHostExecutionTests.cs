using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class PublicationHostExecutionTests
{
    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(5);

    [Fact]
    public async Task EitherHostStopClosesBothHostsAndRetainsTheActualPublisherUntilSettlement()
    {
        var appFailure = new IOException("Controlled Application stop failure.");
        var publicationFailure = new IOException("Controlled publication stop failure.");
        var callbackFailure = new IOException("Controlled publisher callback failure.");
        var workFailure = new InvalidDataException("Controlled publisher work failure.");
        using var app = new ServiceHostFixture { StopFailure = appFailure };
        using var publication = new ServiceHostFixture { StopFailure = publicationFailure };
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = ServiceExecution.RunAsync(async () => await PublicationHostExecution.RunAsync(app, publication,
            () => Assert.True(publication.Started.Task.IsCompleted), () => Assert.False(app.Started.Task.IsCompleted), PublishAsync).ConfigureAwait(true),
            () => publication.CloseAsync(), () => app.CloseAsync());
        Exception[] expected = [appFailure, publicationFailure, callbackFailure, workFailure];
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            publication.StopApplication();
            await app.StopEntered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await publication.StopEntered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await callbackEntered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.False(running.IsCompleted);
            Assert.False(app.Disposed);
            Assert.False(publication.Disposed);
            release.TrySetResult();
            var error = await Record.ExceptionAsync(() => running.WaitAsync(Guard, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            ServiceHostExecutionTests.AssertFailures(error, expected);
            Assert.True(app.Disposed);
            Assert.True(publication.Disposed);
        }, async () =>
        {
            release.TrySetResult();
            if (!app.Disposed) app.StopApplication();
            await TestTaskSettlement.ObserveAsync(running.WaitAsync(CancellationToken.None), error => ServiceHostExecutionTests.OnlyExpected(error, expected)).ConfigureAwait(true);
        }).ConfigureAwait(true);

        async Task PublishAsync(CancellationToken token)
        {
            var registration = token.Register(() => { callbackEntered.TrySetResult(); throw callbackFailure; });
            await using var callback = registration.ConfigureAwait(true);
            entered.TrySetResult();
            await release.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            throw workFailure;
        }
    }

    [Fact]
    public async Task SocketPermissionFailureClosesBothOwnersBeforeStartingTheApplicationOrPublisher()
    {
        var permissions = new IOException("Controlled socket permission failure.");
        using var app = new ServiceHostFixture();
        using var publication = new ServiceHostFixture();
        var published = false;
        var error = await Record.ExceptionAsync(() => ServiceExecution.RunAsync(
            () => PublicationHostExecution.RunAsync(app, publication, () => { }, () => throw permissions,
                _ => { published = true; return Task.CompletedTask; }),
            () => publication.CloseAsync(), () => app.CloseAsync())).ConfigureAwait(true);
        Assert.Same(permissions, error);
        Assert.False(app.Started.Task.IsCompleted);
        Assert.False(published);
        Assert.True(app.StopEntered.Task.IsCompleted);
        Assert.True(publication.StopEntered.Task.IsCompleted);
        Assert.True(app.Disposed);
        Assert.True(publication.Disposed);
    }

    [Fact]
    public async Task ReplicaWithoutAnOutboxKeepsServingUntilStop()
    {
        using var app = new ServiceHostFixture();
        var published = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = ServiceExecution.RunAsync(async () => await PublicationHostExecution.RunAsync(app, publication: null,
            () => { }, () => throw new InvalidOperationException("No publication host exists."),
            _ => { published.TrySetResult(); return Task.CompletedTask; }).ConfigureAwait(true), () => app.CloseAsync());
        await TestTaskSettlement.RunAsync(async () =>
        {
            await published.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.False(running.IsCompleted);
            app.StopApplication();
            await running.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.True(app.Disposed);
        }, async () =>
        {
            if (!app.Disposed) app.StopApplication();
            await running.WaitAsync(CancellationToken.None).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }
}
