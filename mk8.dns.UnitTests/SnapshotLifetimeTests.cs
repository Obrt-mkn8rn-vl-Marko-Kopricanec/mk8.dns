using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class SnapshotLifetimeTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task DisposalKeepsWriterOwnershipUntilPublicationStops(bool useAsyncDisposal, bool failPublication)
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        var zoneId = Guid.NewGuid();
        using (var initial = new FileZoneSnapshotStore(root))
            await initial.ActivateAsync(Snapshot(zoneId, 10), CancellationToken.None).ConfigureAwait(true);

        var reachedPublication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resumePublication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var store = new FileZoneSnapshotStore(root, async cancellationToken =>
        {
            reachedPublication.SetResult();
            await resumePublication.Task.WaitAsync(cancellationToken).ConfigureAwait(true);
            if (failPublication)
                throw new IOException("Injected publication failure during shutdown.");
        });
        var activation = store.ActivateAsync(Snapshot(zoneId, 11), CancellationToken.None).AsTask();
        try
        {
            await reachedPublication.Task.WaitAsync(Timeout).ConfigureAwait(true);
            var queuedActivation = store.ActivateAsync(Snapshot(zoneId, 12), CancellationToken.None).AsTask();
            var queuedRead = store.ReadActiveAsync(zoneId, CancellationToken.None).AsTask();
            var queuedCount = store.CountActiveAsync(CancellationToken.None).AsTask();
            if (!useAsyncDisposal)
                CloseSynchronously(store);
            var drain = store.DisposeAsync().AsTask();
            var repeatedDrain = store.DisposeAsync().AsTask();
            Assert.False(drain.IsCompleted);
            Assert.False(repeatedDrain.IsCompleted);
            Assert.Throws<IOException>(() =>
            {
                using var competing = new FileZoneSnapshotStore(root);
            });
            await AssertQueuedOperationsAreClosedAsync(queuedActivation, queuedRead, queuedCount).ConfigureAwait(true);
            await AssertNewOperationsAreClosedAsync(store, zoneId).ConfigureAwait(true);
            Assert.False(activation.IsCompleted);

            resumePublication.SetResult();
            if (failPublication)
                await Assert.ThrowsAsync<IOException>(() => activation.WaitAsync(Timeout)).ConfigureAwait(true);
            else
                await activation.WaitAsync(Timeout).ConfigureAwait(true);
            await drain.WaitAsync(Timeout).ConfigureAwait(true);
            await repeatedDrain.WaitAsync(Timeout).ConfigureAwait(true);

            await AssertSuccessorCanPublishAsync(root, zoneId, failPublication ? 10 : 11).ConfigureAwait(true);
        }
        finally
        {
            resumePublication.TrySetResult();
            _ = await Record.ExceptionAsync(() => activation.WaitAsync(Timeout)).ConfigureAwait(true);
            await store.DisposeAsync().AsTask().WaitAsync(Timeout).ConfigureAwait(true);
        }
    }

    [Fact]
    public async Task CancelingQueuedWorkDoesNotPreventDisposalDrain()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        var zoneId = Guid.NewGuid();
        var reachedPublication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resumePublication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var store = new FileZoneSnapshotStore(root, cancellationToken =>
        {
            reachedPublication.SetResult();
            return new ValueTask(resumePublication.Task.WaitAsync(cancellationToken));
        });
        var activation = store.ActivateAsync(Snapshot(zoneId, 1), CancellationToken.None).AsTask();
        try
        {
            await reachedPublication.Task.WaitAsync(Timeout).ConfigureAwait(true);
            using var canceled = new CancellationTokenSource();
            var queued = store.ActivateAsync(Snapshot(zoneId, 2), canceled.Token).AsTask();
            await canceled.CancelAsync().ConfigureAwait(true);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued.WaitAsync(Timeout)).ConfigureAwait(true);
            var drain = store.DisposeAsync().AsTask();
            Assert.False(drain.IsCompleted);
            resumePublication.SetResult();
            await activation.WaitAsync(Timeout).ConfigureAwait(true);
            await drain.WaitAsync(Timeout).ConfigureAwait(true);
            using var successor = new FileZoneSnapshotStore(root);
            var active = await successor.ReadActiveAsync(zoneId, CancellationToken.None).ConfigureAwait(true);
            Assert.NotNull(active);
            Assert.Equal(1, active.Revision);
        }
        finally
        {
            resumePublication.TrySetResult();
            _ = await Record.ExceptionAsync(() => activation.WaitAsync(Timeout)).ConfigureAwait(true);
            await store.DisposeAsync().AsTask().WaitAsync(Timeout).ConfigureAwait(true);
        }
    }

    // Exercise the synchronous IDisposable entry point without blocking an async test on the drain.
    private static void CloseSynchronously(FileZoneSnapshotStore store) => store.Dispose();

    private static async Task AssertQueuedOperationsAreClosedAsync(Task queuedActivation, Task<ZoneSnapshot?> queuedRead, Task<uint> queuedCount)
    {
        await Assert.ThrowsAsync<ObjectDisposedException>(() => queuedActivation.WaitAsync(Timeout)).ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => queuedRead.WaitAsync(Timeout)).ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => queuedCount.WaitAsync(Timeout)).ConfigureAwait(true);
    }

    private static async Task AssertNewOperationsAreClosedAsync(FileZoneSnapshotStore store, Guid zoneId)
    {
        await Assert.ThrowsAsync<ObjectDisposedException>(() => store.ActivateAsync(Snapshot(zoneId, 13), CancellationToken.None).AsTask().WaitAsync(Timeout)).ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => store.ReadActiveAsync(zoneId, CancellationToken.None).AsTask().WaitAsync(Timeout)).ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => store.CountActiveAsync(CancellationToken.None).AsTask().WaitAsync(Timeout)).ConfigureAwait(true);
    }

    private static async Task AssertSuccessorCanPublishAsync(string root, Guid zoneId, long expectedRevision)
    {
        using var successor = new FileZoneSnapshotStore(root);
        var active = await successor.ReadActiveAsync(zoneId, CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(active);
        Assert.Equal(expectedRevision, active.Revision);
        await successor.ActivateAsync(Snapshot(zoneId, 12), CancellationToken.None).ConfigureAwait(true);
        active = await successor.ReadActiveAsync(zoneId, CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(active);
        Assert.Equal(12, active.Revision);
    }

    private static ZoneSnapshot Snapshot(Guid zoneId, uint revision) => new(zoneId, DnsName.Parse("example.org."), revision, revision, [1]);
}
