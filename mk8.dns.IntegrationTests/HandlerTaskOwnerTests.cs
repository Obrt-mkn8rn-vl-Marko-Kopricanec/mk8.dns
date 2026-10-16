using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class HandlerTaskOwnerTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SealingJoinsAnOwnerWhoseDownstreamHasNotReturnedItsTask(bool fault)
    {
        var owners = new HandlerTaskOwners();
        using var released = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var downstream = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failure = new IOException("Controlled downstream fault.");
        var actual = Task.Run(() => owners.InvokeAsync(() =>
        {
            entered.TrySetResult();
            if (!released.Wait(TimeSpan.FromSeconds(20), CancellationToken.None)) throw new TimeoutException("Downstream publication was not released.");
            return downstream.Task.WaitAsync(CancellationToken.None);
        }));
        Task? closing = null;
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(20), TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            closing = owners.SealAsync();
            Assert.Same(closing, owners.SealAsync()); Assert.False(closing.IsCompleted);
            var invoked = false;
            await Assert.ThrowsAsync<ObjectDisposedException>(() => owners.InvokeAsync(() => { invoked = true; return Task.CompletedTask; })).ConfigureAwait(true);
            Assert.False(invoked);
            released.Set(); Assert.False(closing.IsCompleted);
            if (fault) downstream.SetException(failure); else downstream.SetResult();
        }, async () =>
        {
            released.Set();
            if (fault) downstream.TrySetException(failure); else downstream.TrySetResult();
            var drain = closing ?? owners.SealAsync();
            await TestTaskSettlement.AllAsync(
                () => TestTaskSettlement.ObserveAsync(actual.WaitAsync(CancellationToken.None), error => fault && ReferenceEquals(error, failure)),
                () => TestTaskSettlement.ObserveAsync(drain.WaitAsync(CancellationToken.None), error => fault && ReferenceEquals(error, failure))).ConfigureAwait(true);
        }).ConfigureAwait(true);
        Assert.True(actual.IsCompleted); Assert.True(owners.SealAsync().IsCompleted);
    }

    [Fact]
    public async Task SynchronousCompletionAndThrowAreBothOwnedBeforeSealing()
    {
        var owners = new HandlerTaskOwners();
        var success = owners.InvokeAsync(() => Task.CompletedTask);
        var failure = new InvalidOperationException("Controlled synchronous downstream failure.");
        var failed = owners.InvokeAsync(() => throw failure);
        await success.WaitAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.Same(failure, await Record.ExceptionAsync(() => failed.WaitAsync(CancellationToken.None)).ConfigureAwait(true));
        var independent = new IOException("Controlled second synchronous failure.");
        var second = owners.InvokeAsync(() => throw independent);
        Assert.Same(independent, await Record.ExceptionAsync(() => second.WaitAsync(CancellationToken.None)).ConfigureAwait(true));
        var closing = owners.SealAsync();
        var combined = await Assert.ThrowsAsync<AggregateException>(() => closing.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
        Assert.Collection(combined.InnerExceptions, error => Assert.Same(failure, error), error => Assert.Same(independent, error));
        Assert.Same(closing, owners.SealAsync());
    }
}
