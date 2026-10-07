using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Npgsql;

namespace Mk8.Dns.Application.DAL;

public sealed class PostgresControlPlaneStore : IControlPlaneStore, IZoneResigningStore, IAsyncDisposable
{
    private const string OperationColumns = "tenant_id,operation_id,fingerprint,actor,target_node,zone_id,origin,revision,serial,payload,content_hash,activated";
    private const string SchemaSql = """
                CREATE TABLE IF NOT EXISTS mk8_control_metadata(singleton boolean PRIMARY KEY CHECK(singleton), schema_version integer NOT NULL, epoch uuid NOT NULL, writer_id uuid NOT NULL);
                CREATE TABLE IF NOT EXISTS mk8_zones(zone_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,origin bytea NOT NULL,revision bigint NOT NULL CHECK(revision>0),serial bigint NOT NULL CHECK(serial BETWEEN 0 AND 4294967295),payload bytea NOT NULL,content_hash text NOT NULL);
                CREATE TABLE IF NOT EXISTS mk8_operations(tenant_id uuid NOT NULL,operation_id uuid NOT NULL,fingerprint text NOT NULL,actor text NOT NULL,target_node text NOT NULL,zone_id uuid NOT NULL REFERENCES mk8_zones(zone_id),origin bytea NOT NULL,revision bigint NOT NULL,serial bigint NOT NULL,payload bytea NOT NULL,content_hash text NOT NULL,activated boolean NOT NULL DEFAULT false,accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),activated_at timestamptz,receipt text,PRIMARY KEY(tenant_id,operation_id),UNIQUE(zone_id,revision));
                CREATE INDEX IF NOT EXISTS mk8_pending_operations ON mk8_operations(accepted_at,zone_id,revision) WHERE NOT activated;
                """;
    private readonly NpgsqlDataSource source;
    private readonly NpgsqlConnection lease;
    private readonly Guid writerId;
    private readonly Lock lifetimeLock = new();
    private readonly CancellationTokenSource admissionClosed = new();
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource terminal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int operations;
    private bool closing;
    private bool initialized;
    private int initializationStarted;

    public PostgresControlPlaneStore(string connectionString)
    {
        ArgumentException.ThrowIfNullOrEmpty(connectionString);
        var configured = new NpgsqlConnectionStringBuilder(connectionString);
        if (configured.Host is null || !Path.IsPathFullyQualified(configured.Host) || configured.Host.Contains(',', StringComparison.Ordinal))
            throw new ArgumentException("This controller profile requires one local PostgreSQL Unix socket directory.", nameof(connectionString));
        writerId = Guid.NewGuid();
        var settings = new NpgsqlConnectionStringBuilder(connectionString) { Pooling = false };
        source = NpgsqlDataSource.Create(connectionString);
        try
        {
            lease = new NpgsqlConnection(settings.ConnectionString);
        }
        catch
        {
            source.Dispose();
            throw;
        }
    }

    public async ValueTask InitializeAsync(Guid epoch, CancellationToken cancellationToken)
    {
        if (epoch == Guid.Empty)
            throw new ArgumentException("A configured controller epoch is required.", nameof(epoch));
        using var registration = Register(initializing: true);
        if (Interlocked.Exchange(ref initializationStarted, 1) != 0)
            throw new InvalidOperationException("Controller storage can only be initialized once.");
        using var admission = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, admissionClosed.Token);
        await lease.OpenAsync(admission.Token).ConfigureAwait(false);
        using (var ownership = Command(lease, null, SqlQuery.AcquireLease))
        {
            if (await ownership.ExecuteScalarAsync(admission.Token).ConfigureAwait(false) is not true)
                throw new InvalidOperationException("Another controller owns this database's writer lease.");
        }
        await InitializeAsync(lease, epoch, writerId, admission.Token).ConfigureAwait(false);
        lock (lifetimeLock)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            initialized = true;
        }
    }

    private static async ValueTask InitializeAsync(NpgsqlConnection connection, Guid epoch, Guid identity, CancellationToken cancellationToken)
    {
        using var durability = Command(connection, null, SqlQuery.ReadDurability);
        var reader = await durability.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        await using (reader.ConfigureAwait(false))
        {
            _ = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(reader.GetString(0), "on", StringComparison.Ordinal) || !string.Equals(reader.GetString(1), "on", StringComparison.Ordinal) || !string.Equals(reader.GetString(2), "on", StringComparison.Ordinal))
                throw new InvalidOperationException("Controller storage requires synchronous durable PostgreSQL commits.");
        }
        var bootstrap = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var bootstrapLifetime = bootstrap.ConfigureAwait(false);
        using var bootstrapLock = Command(connection, bootstrap, SqlQuery.AcquireTransaction);
        _ = await bootstrapLock.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        using var schema = Command(connection, bootstrap, SqlQuery.CreateSchema);
        _ = await schema.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        using var insert = Command(connection, bootstrap, SqlQuery.BootstrapMetadata, epoch, identity);
        _ = await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        using var metadata = Command(connection, bootstrap, SqlQuery.ReadMetadata);
        var metaReader = await metadata.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        await using (metaReader.ConfigureAwait(false))
        {
            if (!await metaReader.ReadAsync(cancellationToken).ConfigureAwait(false) || metaReader.GetInt32(0) != 1 || metaReader.GetGuid(1) != epoch)
                throw new InvalidOperationException("Controller schema, missing committed metadata or publisher epoch requires explicit migration.");
        }
        using var fence = Command(connection, bootstrap, SqlQuery.FenceWriter, identity);
        _ = await fence.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await bootstrap.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IControlTransaction> BeginAsync(CancellationToken cancellationToken)
    {
        Registration? registration = Register();
        NpgsqlConnection? connection = null;
        try
        {
            using var admission = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, admissionClosed.Token);
            connection = await source.OpenConnectionAsync(admission.Token).ConfigureAwait(false);
            var transaction = await connection.BeginTransactionAsync(admission.Token).ConfigureAwait(false);
            try
            {
                using var gate = Command(connection, transaction, SqlQuery.AcquireTransaction);
                _ = await gate.ExecuteNonQueryAsync(admission.Token).ConfigureAwait(false);
                using var ownership = Command(connection, transaction, SqlQuery.ReadWriter);
                if (await ownership.ExecuteScalarAsync(admission.Token).ConfigureAwait(false) is not Guid currentWriter || currentWriter != writerId)
                    throw new InvalidOperationException("Controller writer identity has been fenced by a successor.");
                lock (lifetimeLock)
                    ObjectDisposedException.ThrowIf(closing, this);
                var result = new ControlTransaction(connection, transaction, registration);
                registration = null;
                return result;
            }
            catch
            {
                await transaction.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        catch
        {
            if (connection is not null)
                await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            registration?.Dispose();
        }
    }

    async ValueTask<IZoneResigningTransaction> IZoneResigningStore.BeginAsync(CancellationToken cancellationToken)
        => (ControlTransaction)await BeginAsync(cancellationToken).ConfigureAwait(false);

    public async ValueTask<ZoneOperation?> ReadPendingAsync(CancellationToken cancellationToken)
    {
        using var registration = Register();
        var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var connectionLifetime = connection.ConfigureAwait(false);
        using var command = Command(connection, null, SqlQuery.ReadPending);
        var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        await using var readerLifetime = reader.ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? await PostgresControlPlaneStore.ReadOperationAsync(reader, cancellationToken).ConfigureAwait(false) : null;
    }

    public async ValueTask MarkActivatedAsync(ZoneOperation operation, PublicationReply receipt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(receipt);
        if (!string.Equals(operation.TargetNode, receipt.NodeId, StringComparison.Ordinal) || operation.Snapshot.ZoneId != receipt.ZoneId || operation.Snapshot.Revision != receipt.Revision
            || !string.Equals(operation.Snapshot.ContentHash, receipt.ContentHash, StringComparison.Ordinal) || !string.Equals(receipt.State, "activated", StringComparison.Ordinal))
            throw new InvalidOperationException("Activation receipt does not identify the requested node and generation.");
        var transaction = (ControlTransaction)await BeginAsync(cancellationToken).ConfigureAwait(false);
        await using var lifetime = transaction.ConfigureAwait(false);
        await transaction.MarkActivatedAsync(operation, receipt, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        var ownsCompletion = false;
        lock (lifetimeLock)
        {
            if (!closing)
            {
                closing = true;
                ownsCompletion = true;
                if (operations == 0)
                    drained.SetResult();
            }
        }
        if (!ownsCompletion)
        {
            await terminal.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            return;
        }
        try
        {
            await admissionClosed.CancelAsync().ConfigureAwait(false);
            await drained.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            await lease.DisposeAsync().ConfigureAwait(false);
            await source.DisposeAsync().ConfigureAwait(false);
            admissionClosed.Dispose();
            terminal.SetResult();
        }
        catch (Exception exception)
        {
            terminal.SetException(exception);
            throw;
        }
    }

    private Registration Register(bool initializing = false)
    {
        lock (lifetimeLock)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            if (!initializing && !initialized)
                throw new InvalidOperationException("Controller storage has not completed initialization.");
            operations = checked(operations + 1);
            return new Registration(this);
        }
    }

    private void Release()
    {
        lock (lifetimeLock)
        {
            operations--;
            if (closing && operations == 0)
                drained.SetResult();
        }
    }

    private enum SqlQuery { AcquireLease, ReadDurability, AcquireTransaction, CreateSchema, BootstrapMetadata, ReadMetadata, FenceWriter, ReadWriter, ReadPending, ReadOperation, ReadGeneration, HasPending, ReadZone, ReadOwnership, UpsertZone, AppendOperation, MarkActivated }

    private static NpgsqlCommand Command(NpgsqlConnection connection, NpgsqlTransaction? transaction, SqlQuery query, params object[] parameters)
    {
        var command = new NpgsqlCommand
        {
            Connection = connection,
            Transaction = transaction,
            CommandTimeout = 10,
        };
        SetCommandText(command, query);
        foreach (var parameter in parameters)
            _ = command.Parameters.AddWithValue(parameter);
        return command;
    }

    private static void SetCommandText(NpgsqlCommand command, SqlQuery query)
    {
        switch (query)
        {
            case SqlQuery.AcquireLease:
                command.CommandText = "SELECT pg_try_advisory_lock(5565946963831500800)";
                break;
            case SqlQuery.ReadDurability:
                command.CommandText = "SELECT current_setting('fsync'),current_setting('full_page_writes'),current_setting('synchronous_commit')";
                break;
            case SqlQuery.AcquireTransaction:
                command.CommandText = "SET LOCAL synchronous_commit=on; SELECT pg_advisory_xact_lock(5565946963831500801)";
                break;
            case SqlQuery.CreateSchema:
                command.CommandText = SchemaSql;
                break;
            case SqlQuery.BootstrapMetadata:
                command.CommandText = "INSERT INTO mk8_control_metadata SELECT true,1,$1,$2 WHERE NOT EXISTS(SELECT 1 FROM mk8_zones) AND NOT EXISTS(SELECT 1 FROM mk8_operations) ON CONFLICT(singleton) DO NOTHING";
                break;
            case SqlQuery.ReadMetadata:
                command.CommandText = "SELECT schema_version,epoch FROM mk8_control_metadata WHERE singleton";
                break;
            case SqlQuery.FenceWriter:
                command.CommandText = "UPDATE mk8_control_metadata SET writer_id=$1 WHERE singleton";
                break;
            case SqlQuery.ReadWriter:
                command.CommandText = "SELECT writer_id FROM mk8_control_metadata WHERE singleton";
                break;
            case SqlQuery.ReadPending:
                command.CommandText = "SELECT " + OperationColumns + " FROM mk8_operations WHERE NOT activated AND NOT EXISTS(SELECT 1 FROM mk8_operations earlier WHERE earlier.zone_id=mk8_operations.zone_id AND NOT earlier.activated AND earlier.revision<mk8_operations.revision) ORDER BY accepted_at,zone_id,revision LIMIT 1";
                break;
            case SqlQuery.ReadOperation:
                command.CommandText = "SELECT " + OperationColumns + " FROM mk8_operations WHERE tenant_id=$1 AND operation_id=$2";
                break;
            case SqlQuery.ReadGeneration:
                command.CommandText = "SELECT " + OperationColumns + " FROM mk8_operations WHERE tenant_id=$1 AND zone_id=$2 AND revision=$3";
                break;
            case SqlQuery.HasPending:
                command.CommandText = "SELECT EXISTS(SELECT 1 FROM mk8_operations WHERE zone_id=$1 AND NOT activated)";
                break;
            case SqlQuery.ReadZone:
                command.CommandText = "SELECT zone_id,origin,revision,serial,payload,content_hash FROM mk8_zones WHERE tenant_id=$1 AND zone_id=$2";
                break;
            case SqlQuery.ReadOwnership:
                command.CommandText = "SELECT tenant_id,zone_id,origin FROM mk8_zones";
                break;
            case SqlQuery.UpsertZone:
                command.CommandText = "INSERT INTO mk8_zones VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(zone_id) DO UPDATE SET revision=EXCLUDED.revision,serial=EXCLUDED.serial,payload=EXCLUDED.payload,content_hash=EXCLUDED.content_hash";
                break;
            case SqlQuery.AppendOperation:
                command.CommandText = "INSERT INTO mk8_operations(tenant_id,operation_id,fingerprint,actor,target_node,zone_id,origin,revision,serial,payload,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)";
                break;
            case SqlQuery.MarkActivated:
                command.CommandText = "UPDATE mk8_operations SET activated=true,activated_at=COALESCE(activated_at,clock_timestamp()),receipt=$1 WHERE tenant_id=$2 AND operation_id=$3 AND revision=$4 AND content_hash=$5";
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(query));
        }
    }

    private static async ValueTask<ZoneSnapshot> SnapshotAsync(NpgsqlDataReader reader, int offset, CancellationToken cancellationToken)
    {
        var result = new ZoneSnapshot(reader.GetGuid(offset), DnsName.FromWire(await reader.GetFieldValueAsync<byte[]>(offset + 1, cancellationToken).ConfigureAwait(false)), reader.GetInt64(offset + 2), checked((uint)reader.GetInt64(offset + 3)), await reader.GetFieldValueAsync<byte[]>(offset + 4, cancellationToken).ConfigureAwait(false));
        if (!string.Equals(result.ContentHash, reader.GetString(offset + 5), StringComparison.Ordinal))
            throw new InvalidDataException("Controller snapshot integrity check failed.");
        return result;
    }

    private static async ValueTask<ZoneOperation> ReadOperationAsync(NpgsqlDataReader reader, CancellationToken cancellationToken) => new(reader.GetGuid(0), reader.GetGuid(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), await SnapshotAsync(reader, 5, cancellationToken).ConfigureAwait(false), reader.GetBoolean(11));

    private sealed class ControlTransaction(NpgsqlConnection connection, NpgsqlTransaction transaction, Registration registration) : IZoneResigningTransaction
    {
        public async ValueTask<ZoneOperation?> ReadOperationAsync(Guid tenantId, Guid operationId, CancellationToken cancellationToken)
        {
            using var command = Command(connection, transaction, SqlQuery.ReadOperation, tenantId, operationId);
            var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            await using var readerLifetime = reader.ConfigureAwait(false);
            return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? await PostgresControlPlaneStore.ReadOperationAsync(reader, cancellationToken).ConfigureAwait(false) : null;
        }

        public async ValueTask<ZoneSnapshot?> ReadZoneAsync(Guid tenantId, Guid zoneId, CancellationToken cancellationToken)
        {
            using var command = Command(connection, transaction, SqlQuery.ReadZone, tenantId, zoneId);
            var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            await using var readerLifetime = reader.ConfigureAwait(false);
            return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? await SnapshotAsync(reader, 0, cancellationToken).ConfigureAwait(false) : null;
        }

        public async ValueTask<ZoneOperation?> ReadGenerationAsync(Guid tenantId, Guid zoneId, long revision, CancellationToken cancellationToken)
        {
            using var command = Command(connection, transaction, SqlQuery.ReadGeneration, tenantId, zoneId, revision);
            var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            await using var readerLifetime = reader.ConfigureAwait(false);
            return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? await PostgresControlPlaneStore.ReadOperationAsync(reader, cancellationToken).ConfigureAwait(false) : null;
        }

        public async ValueTask<bool> HasPendingAsync(Guid zoneId, CancellationToken cancellationToken)
        {
            using var command = Command(connection, transaction, SqlQuery.HasPending, zoneId);
            return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is true;
        }

        public async ValueTask<IReadOnlyList<ZoneOwnership>> ReadOwnershipAsync(CancellationToken cancellationToken)
        {
            using var command = Command(connection, transaction, SqlQuery.ReadOwnership);
            var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            await using var readerLifetime = reader.ConfigureAwait(false);
            var results = new List<ZoneOwnership>();
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                results.Add(new ZoneOwnership(reader.GetGuid(0), reader.GetGuid(1), DnsName.FromWire(await reader.GetFieldValueAsync<byte[]>(2, cancellationToken).ConfigureAwait(false))));
            return results.AsReadOnly();
        }

        public async ValueTask AppendAsync(ZoneOperation operation, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(operation);
            var snapshot = operation.Snapshot;
            using var zone = Command(connection, transaction, SqlQuery.UpsertZone, snapshot.ZoneId, operation.TenantId, snapshot.Origin.ToWire(), snapshot.Revision, (long)snapshot.Serial, snapshot.GetPayload(), snapshot.ContentHash);
            _ = await zone.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            using var auditAndOutbox = Command(connection, transaction, SqlQuery.AppendOperation, operation.TenantId, operation.OperationId, operation.Fingerprint, operation.Actor, operation.TargetNode, snapshot.ZoneId, snapshot.Origin.ToWire(), snapshot.Revision, (long)snapshot.Serial, snapshot.GetPayload(), snapshot.ContentHash);
            _ = await auditAndOutbox.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask CommitAsync(CancellationToken cancellationToken) => await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

        internal async ValueTask MarkActivatedAsync(ZoneOperation operation, PublicationReply receipt, CancellationToken cancellationToken)
        {
            using var command = Command(connection, transaction, SqlQuery.MarkActivated, receipt.PublicationId, operation.TenantId, operation.OperationId, operation.Snapshot.Revision, operation.Snapshot.ContentHash);
            if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
                throw new InvalidOperationException("Outbox operation no longer matches its acknowledgement.");
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await transaction.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    await connection.DisposeAsync().ConfigureAwait(false);
                }
                finally
                {
                    registration.Dispose();
                }
            }
        }
    }

    private sealed class Registration(PostgresControlPlaneStore owner) : IDisposable
    {
        private int released;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref released, 1) == 0)
                owner.Release();
        }
    }
}
