using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ServiceCancellationIdentityTests
{
    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(5);

    [Theory]
    [InlineData(false, 0)]
    [InlineData(false, 1)]
    [InlineData(false, 2)]
    [InlineData(true, 0)]
    [InlineData(true, 1)]
    [InlineData(true, 2)]
    public async Task ShutdownOnlyNormalizesCancellationFromItsActualOwner(bool publication, int sourceToken)
    {
        using var host = new ServiceHostFixture();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        OperationCanceledException? failure = null;
        CancellationToken owner = default;
        var running = ServiceExecution.RunAsync(
            async () =>
            {
                if (publication)
                    await PublicationHostExecution.RunAsync(host, publication: null, () => { }, () => { }, SourceAsync).ConfigureAwait(true);
                else
                    await QueryHostExecution.RunAsync(host, SourceAsync).ConfigureAwait(true);
            },
            host.CloseAsync);
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            host.StopApplication();
            await host.StopEntered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.True(owner.IsCancellationRequested);
            Assert.False(running.IsCompleted);
            Assert.False(host.Disposed);
            release.TrySetResult();
            var error = await Record.ExceptionAsync(() => running.WaitAsync(Guard, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            if (sourceToken == 2)
            {
                Assert.Null(error);
            }
            else
            {
                Assert.NotNull(failure);
                Assert.Same(failure, error);
            }
            Assert.True(host.Disposed);
        }, async () =>
        {
            release.TrySetResult();
            if (!host.Disposed) host.StopApplication();
            await TestTaskSettlement.ObserveAsync(running.WaitAsync(CancellationToken.None),
                error => sourceToken != 2 && ReferenceEquals(error, failure)).ConfigureAwait(true);
        }).ConfigureAwait(true);

        async Task SourceAsync(CancellationToken token)
        {
            owner = token;
            var selected = sourceToken == 2 ? token : new CancellationToken(canceled: sourceToken == 1);
            var sourceFailure = new OperationCanceledException("Controlled source cancellation.", selected);
            failure = sourceFailure;
            entered.TrySetResult();
            await release.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            throw sourceFailure;
        }
    }
}
