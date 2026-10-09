using Mk8.Dns.Application.DAL;
using Npgsql;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ControllerLeaseReleaseTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task AcknowledgedReleasePrecedesConnectionCloseAndFollowsTransactionDrain()
    {
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var epoch = Guid.NewGuid();
        var gate = new ReleaseGate();
        var settings = NamedConnection(connection);
        var store = new PostgresControlPlaneStore(settings.ConnectionString, gate.PauseAsync);
        await using var lifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(epoch, CancellationToken.None).ConfigureAwait(true);
        var backend = await ReadLeaseBackendAsync(connection, settings.ApplicationName).ConfigureAwait(true);
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        var disposal = store.DisposeAsync().AsTask();
        var joined = store.DisposeAsync().AsTask();
        try
        {
            Assert.False(gate.Entered.Task.IsCompleted);
            Assert.False(disposal.IsCompleted);
            await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(true);
            await transaction.DisposeAsync().ConfigureAwait(true);
            await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
            await AssertLiveReleasedSessionAsync(connection, backend, epoch).ConfigureAwait(true);
            Assert.False(disposal.IsCompleted);
            Assert.False(joined.IsCompleted);
            _ = await Assert.ThrowsAsync<ObjectDisposedException>(() => store.BeginAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        }
        finally
        {
            await transaction.DisposeAsync().ConfigureAwait(true);
            gate.Continue.TrySetResult();
            await Task.WhenAll(disposal, joined).ConfigureAwait(true);
        }
    }

    [Fact]
    public async Task InitializationFailureStillReleasesItsAcquiredLeaseBeforeClosing()
    {
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var epoch = Guid.NewGuid();
        await InitializeCandidateAsync(connection, epoch).ConfigureAwait(true);
        var gate = new ReleaseGate();
        var settings = NamedConnection(connection);
        var store = new PostgresControlPlaneStore(settings.ConnectionString, gate.PauseAsync);
        await using var lifetime = store.ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => store.InitializeAsync(Guid.NewGuid(), CancellationToken.None).AsTask()).ConfigureAwait(true);
        var backend = await ReadLeaseBackendAsync(connection, settings.ApplicationName).ConfigureAwait(true);
        var disposal = store.DisposeAsync().AsTask();
        try
        {
            await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
            await AssertLiveReleasedSessionAsync(connection, backend, epoch).ConfigureAwait(true);
            Assert.False(disposal.IsCompleted);
        }
        finally
        {
            gate.Continue.TrySetResult();
            await disposal.ConfigureAwait(true);
        }
    }

    [Fact]
    public async Task CleanupFaultIsSharedAndDoesNotRetainTheReleasedDatabaseLease()
    {
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var epoch = Guid.NewGuid();
        var failure = new InvalidOperationException("Controlled cleanup failure.");
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            var store = new PostgresControlPlaneStore(connection, () => ValueTask.FromException(failure));
            await using var lifetime = store.ConfigureAwait(true);
            await store.InitializeAsync(epoch, CancellationToken.None).ConfigureAwait(true);
            Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => store.DisposeAsync().AsTask()).ConfigureAwait(true));
            Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => store.DisposeAsync().AsTask()).ConfigureAwait(true));
            _ = await Assert.ThrowsAsync<ObjectDisposedException>(() => store.BeginAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
            await InitializeCandidateAsync(connection, epoch).ConfigureAwait(true);
        }).ConfigureAwait(true));
    }

    [Fact]
    public async Task UninitializedAndRefusedStoresDoNotReleaseAnotherWritersLease()
    {
        var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
        var epoch = Guid.NewGuid();
        var calls = 0;
        ValueTask CountReleaseAsync()
        {
            calls++;
            return ValueTask.CompletedTask;
        }
        var absent = new PostgresControlPlaneStore(connection, CountReleaseAsync);
        await absent.DisposeAsync().ConfigureAwait(true);
        var owner = new PostgresControlPlaneStore(connection);
        await using var lifetime = owner.ConfigureAwait(true);
        await owner.InitializeAsync(epoch, CancellationToken.None).ConfigureAwait(true);
        var refused = new PostgresControlPlaneStore(connection, CountReleaseAsync);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => refused.InitializeAsync(epoch, CancellationToken.None).AsTask()).ConfigureAwait(true);
        await refused.DisposeAsync().ConfigureAwait(true);
        Assert.Equal(0, calls);
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => InitializeCandidateAsync(connection, epoch)).ConfigureAwait(true);
        await owner.DisposeAsync().ConfigureAwait(true);
        await InitializeCandidateAsync(connection, epoch).ConfigureAwait(true);
    }

    private static NpgsqlConnectionStringBuilder NamedConnection(string connection) => new(connection) { ApplicationName = "mk8-release-" + Guid.NewGuid().ToString("N") };

    private static async Task<int> ReadLeaseBackendAsync(string connectionString, string? name)
    {
        var connection = new NpgsqlConnection(connectionString);
        await using var lifetime = connection.ConfigureAwait(true);
        await connection.OpenAsync().ConfigureAwait(true);
        using var command = new NpgsqlCommand("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND state='idle'", connection);
        _ = command.Parameters.AddWithValue(name!);
        return Assert.IsType<int>(await command.ExecuteScalarAsync().ConfigureAwait(true));
    }

    private static async Task AssertLiveReleasedSessionAsync(string connectionString, int backend, Guid epoch)
    {
        var connection = new NpgsqlConnection(connectionString);
        await using var lifetime = connection.ConfigureAwait(true);
        await connection.OpenAsync().ConfigureAwait(true);
        using var command = new NpgsqlCommand("SELECT count(*) FROM pg_stat_activity WHERE pid=$1 AND state='idle'", connection);
        _ = command.Parameters.AddWithValue(backend);
        Assert.Equal(1L, await command.ExecuteScalarAsync().ConfigureAwait(true));
        await InitializeCandidateAsync(connectionString, epoch).ConfigureAwait(true);
    }

    private static async Task InitializeCandidateAsync(string connection, Guid epoch)
    {
        var store = new PostgresControlPlaneStore(connection);
        await using var lifetime = store.ConfigureAwait(true);
        await store.InitializeAsync(epoch, CancellationToken.None).ConfigureAwait(true);
        var transaction = await store.BeginAsync(CancellationToken.None).ConfigureAwait(true);
        await using var transactionLifetime = transaction.ConfigureAwait(true);
        await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(true);
    }

    private sealed class ReleaseGate
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Continue { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal async ValueTask PauseAsync()
        {
            Entered.TrySetResult();
            await Continue.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
        }
    }
}
