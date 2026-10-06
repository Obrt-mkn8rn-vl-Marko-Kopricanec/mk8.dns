using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Infrastructure;
using Npgsql;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class OutboxTests : IAsyncLifetime
{
    private readonly PostgresFixture postgres = new();
    public Task InitializeAsync() => postgres.InitializeAsync();
    public Task DisposeAsync() => postgres.DisposeAsync();
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LostOrMismatchedReceiptStaysPendingAndDuplicateDeliveryReconciles(bool corruptReceipt)
    {
        var control = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var storeLifetime = store.ConfigureAwait(true);
        var management = new ZoneManagementApplication(store, control.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        var edit = control.Edit();
        var accepted = await management.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        var replica = new ReplicaFixture(control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenAsync().ConfigureAwait(true);
        var publisher = new OutboxPublisher(store, replica.Signer, new InterruptedPublicationClient(replica.Publication!, corruptReceipt));
        if (corruptReceipt)
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => publisher.DispatchOneAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        else
            _ = await Assert.ThrowsAsync<IOException>(() => publisher.DispatchOneAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.True((await replica.Authority.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).DnsReady);
        var pending = await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(pending);
        Assert.False(pending.Activated);
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Null(await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true));
        var status = await management.ExecuteAsync(edit with { Action = "status" }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal("activated", status.State);
        Assert.Equal(accepted.Revision, status.Revision);
        Assert.Equal(accepted.ContentHash, status.ContentHash);
        Assert.False(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
    }
    [Fact]
    public async Task WallClockRollbackCannotDeliverALaterZoneRevisionBeforeItsPendingPredecessor()
    {
        var control = new ControlFixture();
        var connectionString = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var store = new PostgresControlPlaneStore(connectionString);
        await using var storeLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(control.Epoch, CancellationToken.None).ConfigureAwait(true);
        var management = new ZoneManagementApplication(store, control.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        var first = control.Edit();
        var second = control.Edit(1, 43);
        _ = await management.ExecuteAsync(first, CancellationToken.None).ConfigureAwait(true);
        _ = await management.ExecuteAsync(second, CancellationToken.None).ConfigureAwait(true);
        var connection = new NpgsqlConnection(connectionString);
        await using (connection.ConfigureAwait(true))
        {
            await connection.OpenAsync().ConfigureAwait(true);
            using var rollbackClock = new NpgsqlCommand("UPDATE mk8_operations SET accepted_at=CASE WHEN revision=1 THEN now()+interval '1 hour' ELSE now()-interval '1 hour' END", connection);
            _ = await rollbackClock.ExecuteNonQueryAsync().ConfigureAwait(true);
        }
        Assert.Equal(1L, (await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!.Snapshot.Revision);
        var replica = new ReplicaFixture(control);
        await using var replicaLifetime = replica.ConfigureAwait(true);
        await replica.OpenAsync().ConfigureAwait(true);
        var publisher = new OutboxPublisher(store, replica.Signer, replica.Publication!);
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal("activated", (await management.ExecuteAsync(first with { Action = "status" }, CancellationToken.None).ConfigureAwait(true)).State);
        Assert.Equal("accepted", (await management.ExecuteAsync(second with { Action = "status" }, CancellationToken.None).ConfigureAwait(true)).State);
        Assert.Equal(1L, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
        Assert.True(await publisher.DispatchOneAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Equal(2L, (await replica.Store.ReadActiveAsync(control.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
        Assert.Null(await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true));
    }

}
