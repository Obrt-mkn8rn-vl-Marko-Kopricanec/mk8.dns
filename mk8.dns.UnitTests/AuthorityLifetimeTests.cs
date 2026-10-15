using Mk8.Dns.Application;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthorityLifetimeTests
{
    [Fact]
    public async Task ShutdownKeepsSnapshotAdmissionAndWriterLeaseUntilPublicationSettles()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fixture = new PublicationFixture(async _ =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
        });
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var publisher = await fixture.OpenAsync().ConfigureAwait(true);
        var owner = new ControlRuntime(fixture.Store, publisher);
        await using var ownerLifetime = owner.ConfigureAwait(true);
        var prepared = fixture.Prepare(PublicationFixture.Snapshot(1, 1));
        _ = await publisher.ExecuteAsync(prepared, CancellationToken.None).ConfigureAwait(true);
        var activation = publisher.ExecuteAsync(fixture.Activate(prepared.PublicationId), CancellationToken.None).AsTask();
        Task<ZoneSnapshot?>? reading = null;
        Task? closing = null;
        await TestTaskSettlement.RunAsync(async () =>
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
            closing = owner.DisposeAsync().AsTask();
            Assert.False(closing.IsCompleted);
            reading = fixture.Store.ReadActiveAsync(PublicationFixture.ZoneId, CancellationToken.None).AsTask();
            Assert.False(reading.IsCompleted);
            Assert.Throws<IOException>(() => { using var contender = new FileZoneSnapshotStore(Path.Combine(fixture.Root, "state")); });
            release.TrySetResult();
            Assert.Equal("activated", (await activation.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true)).State);
            await ObserveReadAsync(reading.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
            await closing.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
        }, async () =>
        {
            release.TrySetResult();
            await TestTaskSettlement.RunAsync(async () =>
            {
                await activation.WaitAsync(CancellationToken.None).ConfigureAwait(true);
                if (reading is not null) await ObserveReadAsync(reading.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
            }, async () => await owner.DisposeAsync().ConfigureAwait(true)).ConfigureAwait(true);
        }).ConfigureAwait(true);
        Assert.Same(closing, owner.DisposeAsync().AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => fixture.Store.CountActiveAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        var replacement = new FileZoneSnapshotStore(Path.Combine(fixture.Root, "state"));
        await using var replacementLifetime = replacement.ConfigureAwait(true);
        Assert.Equal(1u, await replacement.CountActiveAsync(CancellationToken.None).ConfigureAwait(true));
    }

    private static async Task ObserveReadAsync(Task<ZoneSnapshot?> reading)
    {
        try { _ = await reading.WaitAsync(CancellationToken.None).ConfigureAwait(true); }
        catch (ObjectDisposedException) { /* Publication may finish before the separately queued reader is admitted. */ }
    }

}
