using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Infrastructure;
using Npgsql;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ControlPlaneTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task EditCommitsAssignedSerialSnapshotAuditAndOutboxTogether()
    {
        var fixture = new ControlFixture();
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var store = new PostgresControlPlaneStore(connection);
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        var application = new ZoneManagementApplication(store, fixture.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        var edit = fixture.Edit();
        var accepted = await application.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal("accepted", accepted.State);
        Assert.Equal(1L, accepted.Revision);
        Assert.Equal(1u, accepted.Serial);
        var pending = await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(pending);
        Assert.Equal(accepted.ContentHash, pending.Snapshot.ContentHash);
        Assert.Equal("operator-test", pending.Actor);
        Assert.Equal(ControlFixture.Node, pending.TargetNode);
        var status = await application.ExecuteAsync(edit with { Action = "status", Records = Array.Empty<ZoneRecordData>() }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(accepted, status);
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var transactionLifetime = transaction.ConfigureAwait(true);
        Assert.Equal(accepted.ContentHash, (await transaction.ReadZoneAsync(fixture.Tenant, fixture.Zone, CancellationToken.None).ConfigureAwait(true))!.ContentHash);
        Assert.Single(await transaction.ReadOwnershipAsync(CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task AbortedEditPreservesOnlyTheOriginalZoneAuditAndOutbox()
    {
        var fixture = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        var application = new ZoneManagementApplication(store, fixture.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        var edit = fixture.Edit();
        _ = await application.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        var original = (await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!;
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using (transaction.ConfigureAwait(true))
        {
            var snapshot = new Mk8.Dns.Domain.ZoneSnapshot(original.Snapshot.ZoneId, original.Snapshot.Origin, 2, 2, original.Snapshot.GetPayload());
            await transaction.AppendAsync(original with { OperationId = Guid.NewGuid(), Snapshot = snapshot }, CancellationToken.None).ConfigureAwait(true);
        }
        var check = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var checkLifetime = check.ConfigureAwait(true);
        Assert.Equal(1L, (await check.ReadZoneAsync(fixture.Tenant, fixture.Zone, CancellationToken.None).ConfigureAwait(true))!.Revision);
        Assert.Equal(original.OperationId, (await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!.OperationId);
    }

    [Fact]
    public async Task IdempotentReplayDoesNotAllocateAnotherRevisionAndChangedIntentConflicts()
    {
        var fixture = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        var application = new ZoneManagementApplication(store, fixture.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        var edit = fixture.Edit();
        var first = await application.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(first, await application.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true));
        var second = await application.ExecuteAsync(fixture.Edit(1, 43), CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2L, second.Revision);
        Assert.Equal(2u, second.Serial);
        Assert.Equal(first, await application.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true));
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => application.ExecuteAsync(fixture.Edit(0, 44, edit.OperationId), CancellationToken.None).AsTask()).ConfigureAwait(true);
    }

    [Fact]
    public async Task ParallelEditsWithOneExpectedRevisionHaveOneWinner()
    {
        var fixture = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        var application = new ZoneManagementApplication(store, fixture.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        var first = TryEditAsync(application, fixture.Edit(0, 42));
        var second = TryEditAsync(application, fixture.Edit(0, 43));
        var results = await Task.WhenAll(first, second).ConfigureAwait(true);
        Assert.Single(results, result => result);
        var pending = await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.NotNull(pending);
        Assert.Equal(1L, pending.Snapshot.Revision);
    }

    [Fact]
    public async Task UnauthorizedEditHasNoDurableSideEffects()
    {
        var fixture = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = store.ConfigureAwait(true);
        var application = new ZoneManagementApplication(store, fixture.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => application.ExecuteAsync(fixture.Edit() with { TenantId = Guid.NewGuid() }, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => application.ExecuteAsync(fixture.Edit() with { Credential = new byte[32] }, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Null(await store.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true));
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var transactionLifetime = transaction.ConfigureAwait(true);
        Assert.Empty(await transaction.ReadOwnershipAsync(CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task RestartPreservesPendingPublicationAndRejectsEpochReset()
    {
        var fixture = new ControlFixture();
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var store = new PostgresControlPlaneStore(connection);
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        var edit = fixture.Edit();
        var application = new ZoneManagementApplication(store, fixture.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        var accepted = await application.ExecuteAsync(edit, CancellationToken.None).ConfigureAwait(true);
        await store.DisposeAsync().ConfigureAwait(true);
        var reopened = new PostgresControlPlaneStore(connection);
        await using var reopenedStartupLifetime = reopened.ConfigureAwait(true);
        await reopened.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var lifetime = reopened.ConfigureAwait(true);
        Assert.Equal(accepted.ContentHash, (await reopened.ReadPendingAsync(CancellationToken.None).ConfigureAwait(true))!.Snapshot.ContentHash);
        await reopened.DisposeAsync().ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => InitializeCandidateAsync(connection, Guid.NewGuid(), CancellationToken.None).AsTask()).ConfigureAwait(true);
        await InitializeCandidateAsync(connection, fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
    }

    [Fact]
    public async Task MissingCommittedControllerMetadataCannotBootstrapANewEpoch()
    {
        var fixture = new ControlFixture();
        var connectionString = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var store = new PostgresControlPlaneStore(connectionString);
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        var application = new ZoneManagementApplication(store, fixture.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        _ = await application.ExecuteAsync(fixture.Edit(), CancellationToken.None).ConfigureAwait(true);
        await store.DisposeAsync().ConfigureAwait(true);
        var connection = new NpgsqlConnection(connectionString);
        await using (connection.ConfigureAwait(true))
        {
            await connection.OpenAsync().ConfigureAwait(true);
            using var command = new NpgsqlCommand("DELETE FROM mk8_control_metadata", connection);
            _ = await command.ExecuteNonQueryAsync().ConfigureAwait(true);
        }
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => InitializeCandidateAsync(connectionString, fixture.Epoch, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => InitializeCandidateAsync(connectionString, Guid.NewGuid(), CancellationToken.None).AsTask()).ConfigureAwait(true);
    }

    private static async Task<bool> TryEditAsync(ZoneManagementApplication application, ManagementRequest request)
    {
        try
        {
            _ = await application.ExecuteAsync(request, CancellationToken.None).ConfigureAwait(true);
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    [Theory]
    [InlineData("example.")]
    [InlineData("child.example.")]
    public async Task ScopedCredentialsCannotStealZoneIdentityOrClaimAnOverlappingOrigin(string otherOrigin)
    {
        var first = new ControlFixture();
        var other = new ControlFixture();
        var store = new PostgresControlPlaneStore(await postgres.ResetDatabaseAsync().ConfigureAwait(true));
        await using var storeLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(first.Epoch, CancellationToken.None).ConfigureAwait(true);
        var otherGrant = other.Grant(otherOrigin);
        var authorizer = new ScopedManagementAuthorizer([first.Grant(), otherGrant, other.Grant() with { ZoneId = first.Zone }], TimeProvider.System);
        var application = new ZoneManagementApplication(store, authorizer, new ZoneBundleAdapter(), ControlFixture.Node);
        _ = await application.ExecuteAsync(first.Edit(), CancellationToken.None).ConfigureAwait(true);
        var steal = other.Edit() with { ZoneId = first.Zone };
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => application.ExecuteAsync(steal, CancellationToken.None).AsTask()).ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => application.ExecuteAsync(other.Edit(originText: otherOrigin), CancellationToken.None).AsTask()).ConfigureAwait(true);
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var transactionLifetime = transaction.ConfigureAwait(true);
        Assert.Single(await transaction.ReadOwnershipAsync(CancellationToken.None).ConfigureAwait(true));
        Assert.Null(await transaction.ReadZoneAsync(other.Tenant, other.Zone, CancellationToken.None).ConfigureAwait(true));
    }

    [Fact]
    public async Task DisposalRetainsWriterLeaseUntilAdmittedTransactionDrains()
    {
        var fixture = new ControlFixture();
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var store = new PostgresControlPlaneStore(connection);
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        var queued = store.BeginAsync(CancellationToken.None).AsTask();
        await WaitForQueuedTransactionAsync(connection).ConfigureAwait(true);
        var disposal = store.DisposeAsync().AsTask();
        try
        {
            Assert.False(disposal.IsCompleted);
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => InitializeCandidateAsync(connection, fixture.Epoch, CancellationToken.None).AsTask()).ConfigureAwait(true);
            _ = await Assert.ThrowsAsync<ObjectDisposedException>(() => store.BeginAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
            await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(true);
        }
        finally
        {
            await transaction.DisposeAsync().ConfigureAwait(true);
            await disposal.ConfigureAwait(true);
        }
        var successor = new PostgresControlPlaneStore(connection);
        await using var successorStartupLifetime = successor.ConfigureAwait(true);
        await successor.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var successorLifetime = successor.ConfigureAwait(true);
        var admitted = await successor.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var admittedLifetime = admitted.ConfigureAwait(true);
        await admitted.CommitAsync(CancellationToken.None).ConfigureAwait(true);
    }

    [Fact]
    public async Task LostDatabaseSessionIsFencedBeforeAnOldControllerCanStartAnotherEdit()
    {
        var fixture = new ControlFixture();
        var connectionString = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var oldSettings = new NpgsqlConnectionStringBuilder(connectionString) { ApplicationName = "mk8-old-writer" };
        var store = new PostgresControlPlaneStore(oldSettings.ConnectionString);
        await using var storeStartupLifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var oldLifetime = store.ConfigureAwait(true);
        var connection = new NpgsqlConnection(connectionString);
        await using (connection.ConfigureAwait(true))
        {
            await connection.OpenAsync().ConfigureAwait(true);
            using var terminate = new NpgsqlCommand("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mk8-old-writer' AND state='idle'", connection);
            Assert.Equal(true, await terminate.ExecuteScalarAsync().ConfigureAwait(true));
        }
        var successor = new PostgresControlPlaneStore(connectionString);
        await using var successorStartupLifetime = successor.ConfigureAwait(true);
        await successor.InitializeAsync(fixture.Epoch, CancellationToken.None).ConfigureAwait(true);
        await using var successorLifetime = successor.ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => store.BeginAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        var application = new ZoneManagementApplication(successor, fixture.Authorizer(), new ZoneBundleAdapter(), ControlFixture.Node);
        Assert.Equal(1L, (await application.ExecuteAsync(fixture.Edit(), CancellationToken.None).ConfigureAwait(true)).Revision);
    }
    private static async ValueTask InitializeCandidateAsync(string connection, Guid epoch, CancellationToken cancellationToken)
    {
        var candidate = new PostgresControlPlaneStore(connection);
        await using var lifetime = candidate.ConfigureAwait(true);
        await candidate.InitializeAsync(epoch, cancellationToken).ConfigureAwait(true);
    }

    private static async Task WaitForQueuedTransactionAsync(string connectionString)
    {
        var connection = new NpgsqlConnection(connectionString);
        await using var connectionLifetime = connection.ConfigureAwait(true);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await connection.OpenAsync(timeout.Token).ConfigureAwait(true);
        using var command = new NpgsqlCommand("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND wait_event='advisory'", connection);
        while (await command.ExecuteScalarAsync(timeout.Token).ConfigureAwait(true) is not long count || count == 0)
            await Task.Delay(TimeSpan.FromMilliseconds(10), timeout.Token).ConfigureAwait(true);
    }

}
