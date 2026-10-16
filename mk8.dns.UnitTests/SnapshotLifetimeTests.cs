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
        await WriteInitialSnapshotAsync(root, zoneId).ConfigureAwait(true);

        var reachedPublication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resumePublication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var publicationError = new IOException("Injected publication failure during shutdown.");
        var store = new FileZoneSnapshotStore(root, async cancellationToken =>
        {
            reachedPublication.SetResult();
            await resumePublication.Task.WaitAsync(cancellationToken).ConfigureAwait(true);
            if (failPublication)
                throw publicationError;
        });
        await using var storeLifetime = store.ConfigureAwait(true);
        Task? queuedActivation = null;
        Task<ZoneSnapshot?>? queuedRead = null;
        Task<uint>? queuedCount = null;
        Task? drain = null;
        Task? repeatedDrain = null;
        var activation = store.ActivateAsync(Snapshot(zoneId, 11), CancellationToken.None).AsTask();
        await TestTaskSettlement.RunAsync(async () =>
        {
            await reachedPublication.Task.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            queuedActivation = store.ActivateAsync(Snapshot(zoneId, 12), CancellationToken.None).AsTask();
            queuedRead = store.ReadActiveAsync(zoneId, CancellationToken.None).AsTask();
            queuedCount = store.CountActiveAsync(CancellationToken.None).AsTask();
            if (!useAsyncDisposal)
                CloseSynchronously(store);
            drain = store.DisposeAsync().AsTask();
            repeatedDrain = store.DisposeAsync().AsTask();
            AssertWriterLeaseRetained(root, drain, repeatedDrain);
            await AssertQueuedOperationsAreClosedAsync(queuedActivation, queuedRead, queuedCount).ConfigureAwait(true);
            await AssertNewOperationsAreClosedAsync(store, zoneId).ConfigureAwait(true);
            Assert.False(activation.IsCompleted);

            resumePublication.SetResult();
            if (failPublication)
                await Assert.ThrowsAsync<IOException>(() => activation.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            else
                await activation.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await drain.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await repeatedDrain.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);

            await AssertSuccessorCanPublishAsync(root, zoneId, failPublication ? 10 : 11).ConfigureAwait(true);
        }, () => RetirePublicationAsync(store, resumePublication, activation.WaitAsync(CancellationToken.None),
            failPublication ? publicationError : null, drain?.WaitAsync(CancellationToken.None), repeatedDrain?.WaitAsync(CancellationToken.None),
            [queuedActivation?.WaitAsync(CancellationToken.None), queuedRead?.WaitAsync(CancellationToken.None), queuedCount?.WaitAsync(CancellationToken.None)])).ConfigureAwait(true);
    }

    [Fact]
    public async Task CancelingQueuedWorkDoesNotPreventDisposalDrain()
    {
        using var directory = new TemporaryDirectory();
        var root = Path.Combine(directory.Path, "state");
        var zoneId = Guid.NewGuid();
        var reachedPublication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resumePublication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = new FileZoneSnapshotStore(root, cancellationToken =>
        {
            reachedPublication.SetResult();
            return new ValueTask(resumePublication.Task.WaitAsync(cancellationToken));
        });
        await using var storeLifetime = store.ConfigureAwait(true);
        var activation = store.ActivateAsync(Snapshot(zoneId, 1), CancellationToken.None).AsTask();
        try
        {
            await reachedPublication.Task.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            using var canceled = new CancellationTokenSource();
            var queued = store.ActivateAsync(Snapshot(zoneId, 2), canceled.Token).AsTask();
            await canceled.CancelAsync().ConfigureAwait(true);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            var drain = store.DisposeAsync().AsTask();
            Assert.False(drain.IsCompleted);
            resumePublication.SetResult();
            await activation.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await drain.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var successor = new FileZoneSnapshotStore(root);
            await using var successorLifetime = successor.ConfigureAwait(true);
            var active = await successor.ReadActiveAsync(zoneId, CancellationToken.None).ConfigureAwait(true);
            Assert.NotNull(active);
            Assert.Equal(1, active.Revision);
        }
        finally
        {
            resumePublication.TrySetResult();
            _ = await Record.ExceptionAsync(() => activation.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            await store.DisposeAsync().AsTask().WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        }
    }

    private static async Task WriteInitialSnapshotAsync(string root, Guid zoneId)
    {
        var initial = new FileZoneSnapshotStore(root);
        await using var lifetime = initial.ConfigureAwait(true);
        await initial.ActivateAsync(Snapshot(zoneId, 10), CancellationToken.None).ConfigureAwait(true);
    }

    private static void AssertWriterLeaseRetained(string root, Task first, Task repeated)
    {
        Assert.False(first.IsCompleted);
        Assert.False(repeated.IsCompleted);
        Assert.Throws<IOException>(() =>
        {
            using var competing = new FileZoneSnapshotStore(root);
        });
    }

    private static async Task RetirePublicationAsync(FileZoneSnapshotStore store, TaskCompletionSource resume, Task activation,
        Exception? expectedFailure, Task? firstClose, Task? repeatedClose, Task?[] queued)
    {
        var actualClose = firstClose ?? store.DisposeAsync().AsTask();
        resume.TrySetResult();
        await TestTaskSettlement.AllAsync(
            () => TestTaskSettlement.ObserveAsync(activation.WaitAsync(CancellationToken.None), error => ReferenceEquals(error, expectedFailure)),
            () => TestTaskSettlement.AllAsync([.. queued.OfType<Task>().Select(task => (Func<Task>)(() =>
                TestTaskSettlement.ObserveAsync(task.WaitAsync(CancellationToken.None), error => error is ObjectDisposedException)))]),
            () => TestTaskSettlement.WaitAsync(actualClose.WaitAsync(CancellationToken.None), Timeout),
            async () => { if (repeatedClose is not null) await TestTaskSettlement.WaitAsync(repeatedClose.WaitAsync(CancellationToken.None), Timeout).ConfigureAwait(true); }).ConfigureAwait(true);
    }

    // Exercise the synchronous IDisposable entry point without blocking an async test on the drain.
    private static void CloseSynchronously(FileZoneSnapshotStore store) => store.Dispose();

    private static async Task AssertQueuedOperationsAreClosedAsync(Task queuedActivation, Task<ZoneSnapshot?> queuedRead, Task<uint> queuedCount)
    {
        await Assert.ThrowsAsync<ObjectDisposedException>(() => queuedActivation.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => queuedRead.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => queuedCount.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
    }

    private static async Task AssertNewOperationsAreClosedAsync(FileZoneSnapshotStore store, Guid zoneId)
    {
        await Assert.ThrowsAsync<ObjectDisposedException>(() => store.ActivateAsync(Snapshot(zoneId, 13), CancellationToken.None).AsTask().WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => store.ReadActiveAsync(zoneId, CancellationToken.None).AsTask().WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => store.CountActiveAsync(CancellationToken.None).AsTask().WaitAsync(Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
    }

    private static async Task AssertSuccessorCanPublishAsync(string root, Guid zoneId, long expectedRevision)
    {
        var successor = new FileZoneSnapshotStore(root);
        await using var successorLifetime = successor.ConfigureAwait(true);
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
