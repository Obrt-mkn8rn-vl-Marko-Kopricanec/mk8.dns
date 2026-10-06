using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Infrastructure;
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
    private static async ValueTask InitializeCandidateAsync(string connection, Guid epoch, CancellationToken cancellationToken)
    {
        var candidate = new PostgresControlPlaneStore(connection);
        await using var lifetime = candidate.ConfigureAwait(true);
        await candidate.InitializeAsync(epoch, cancellationToken).ConfigureAwait(true);
    }

}
