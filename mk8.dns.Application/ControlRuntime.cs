using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using Grpc.Core;
using Npgsql;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Transport;

namespace Mk8.Dns.Application;

internal sealed class ControlRuntime : IAsyncDisposable
{
    private PostgresControlPlaneStore? store;
    private P256PublicationAuthenticator? authenticator;
    private FilePublicationJournal? journal;
    private UnixControlClient? client;
    private OutboxPublisher? publisher;
    private ZoneResigningApplication? resigning;
    private DnssecRenewalScope[] renewalScopes = [];
    private TimeSpan signingScan;
    private TimeSpan dispatchInterval;
    private readonly List<EcdsaP256DnssecSigningKey> dnssecKeys = [];
    internal AuthoritativeApplication? Authority { get; private set; }
    internal ZoneManagementApplication? Management { get; private set; }
    internal ZonePublicationApplication? Publication { get; private set; }

    private ControlConfiguration? prepared;
    private Dictionary<Guid, DnsName>? preparedZones;
    private ZoneBundleAdapter? preparedCodec;
    private string? connectionString;
    private ScopedManagementAuthorizer? managementAuthorizer;

    internal void Prepare(ApplicationSettings settings, DnsServiceSecrets secrets)
    {
        var configuration = PrepareSecrets(settings, secrets);
        if (configuration is null) return;
        dispatchInterval = TimeSpan.FromMilliseconds(configuration.DispatchIntervalMilliseconds);
        var zones = configuration.Zones.ToDictionary(zone => zone.ZoneId, zone => DnsName.Parse(zone.Origin));
        var controller = string.Equals(settings.Role, "controller", StringComparison.Ordinal);
        if (!controller && !string.Equals(configuration.TargetNode, settings.NodeId, StringComparison.Ordinal))
            throw new InvalidDataException("Publisher trust targets a different replica.");
        var identity = new P256PublicationAuthenticator(configuration.Epoch, configuration.TargetNode, zones, secrets.Text(configuration.KeySecret, 4096), controller);
        authenticator = identity;
        if (!controller && (configuration.SigningScanSeconds != 60 || configuration.Zones.Any(zone => zone.SigningKeySecret is not null
            || zone.SignatureLifetimeSeconds != 604_800 || zone.DnskeyTtl != 3600 || zone.RenewBeforeSeconds is not null)))
        {
            throw new InvalidDataException("A serving replica cannot take private signing configuration.");
        }

        if (controller)
        {
            renewalScopes = [.. configuration.Zones.Where(zone => zone.SigningKeySecret is not null).Select(zone => new DnssecRenewalScope(zone.ZoneId, DnsName.Parse(zone.Origin), zone.SignatureLifetimeSeconds, zone.RenewBeforeSeconds))];
            if (configuration.SigningScanSeconds is 0 or > 300 || renewalScopes.Any(scope => configuration.SigningScanSeconds > scope.RenewBeforeSeconds / 2)
                || (renewalScopes.Length == 0 && configuration.SigningScanSeconds != 60))
            {
                throw new InvalidDataException("Invalid signing renewal scan interval.");
            }

            signingScan = TimeSpan.FromSeconds(configuration.SigningScanSeconds);
        }
        var codec = controller ? CreateCodec(configuration, secrets) : new ZoneBundleAdapter();
        if (controller)
        {
            if (configuration.ConnectionStringSecret is null || configuration.PublicationSocket is null || configuration.Grants is not { Length: > 0 and <= 64 })
                throw new InvalidDataException("Controller database, target and management grants are required.");
            if (!Path.IsPathFullyQualified(configuration.PublicationSocket)) throw new InvalidDataException("SecretPublicationPathInvalid");
            PrivateUnixSocket.ValidatePath(configuration.PublicationSocket);
            var grants = configuration.Grants.Select(CreateGrant).ToArray();
            if (grants.Any(grant => !zones.TryGetValue(grant.ZoneId, out var origin) || !origin.Equals(grant.Origin)))
                throw new InvalidDataException("Management grants exceed the publisher scope.");
            managementAuthorizer = new ScopedManagementAuthorizer(grants, TimeProvider.System);
        }
        else if (configuration.ConnectionStringSecret is not null || configuration.PublicationSocket is not null || configuration.Grants is { Length: > 0 })
        {
            throw new InvalidDataException("A serving replica cannot take controller configuration.");
        }

        prepared = configuration; preparedZones = zones; preparedCodec = codec;
    }

    private ControlConfiguration? PrepareSecrets(ApplicationSettings settings, DnsServiceSecrets secrets)
    {
        var names = new List<string> { "Mode", "Settings", "HostPolicy" };
        if (settings.CookieSecret is not null) names.Add(settings.CookieSecret);
        if (settings.Role is "authoritative-replica") names.Add("TsigMode");
        if (settings.TsigSecret is not null) names.Add(settings.TsigSecret);
        if (settings.ControlSecret is null) { secrets.RequireOnly(names); return null; }
        names.Add(settings.ControlSecret);
        ControlConfiguration? configuration = null;
        try { configuration = JsonSerializer.Deserialize(secrets.JsonText(settings.ControlSecret), ControlConfigurationContext.Default.ControlConfiguration); }
        catch (JsonException) { /* Invalid structured input does not expose secret values. */ }
        if (configuration is null) throw new InvalidDataException("SecretControlInvalid");
        if (configuration.Zones is not { Length: > 0 and <= 64 } || configuration.Zones.Any(zone => zone is null) || configuration.KeySecret is null || configuration.TargetNode is null)
            throw new InvalidDataException("Publisher scope and key are required.");
        DnsServiceSecrets.ValidateName(configuration.KeySecret); names.Add(configuration.KeySecret);
        foreach (var zone in configuration.Zones)
            if (zone.SigningKeySecret is { } signing) { DnsServiceSecrets.ValidateName(signing); names.Add(signing); }
        if (configuration.ConnectionStringSecret is { } database)
        {
            DnsServiceSecrets.ValidateName(database); names.Add(database);
            connectionString = secrets.Text(database, 4096);
            ValidateDatabaseSettings(connectionString);
        }
        secrets.RequireOnly(names);
        if (configuration.DispatchIntervalMilliseconds is < 1 or > 1000) throw new InvalidDataException("SecretDispatchIntervalInvalid");
        return configuration;
    }

    private static void ValidateDatabaseSettings(string connectionString)
    {
        var databaseValid = false;
        try
        {
            var databaseSettings = new NpgsqlConnectionStringBuilder(connectionString);
            if (!databaseSettings.ShouldSerialize("Host") || !databaseSettings.ShouldSerialize("Database")
                || !databaseSettings.ShouldSerialize("Username") || !databaseSettings.ShouldSerialize("Port")
                || string.IsNullOrWhiteSpace(databaseSettings.Host) || string.IsNullOrWhiteSpace(databaseSettings.Database)
                || string.IsNullOrWhiteSpace(databaseSettings.Username) || databaseSettings.Port is < 1 or > 65535)
            {
                throw new InvalidDataException("SecretDatabaseScopeMissing");
            }

            databaseValid = true;
        }
        catch (ArgumentException) { /* Diagnostics may include confidential connection settings. */ }
        if (!databaseValid) throw new InvalidDataException("SecretDatabaseInvalid");
        PostgresControlPlaneStore.ValidateLocalConnectionString(connectionString);
    }

    internal async ValueTask InitializeAsync(ApplicationSettings settings, FileZoneSnapshotStore snapshots, IDnsCookieService? cookies, ITsigService? tsig, IDnsResponseLimiter? limiter)
    {
        if (prepared is not { } configuration || preparedZones is not { } zones || preparedCodec is not { } codec || authenticator is not { } identity)
            return;
        if (settings.Role is "controller")
            await InitializeControllerAsync(configuration, zones, codec, identity).ConfigureAwait(false);
        else
            await InitializeReplicaAsync(settings, configuration, snapshots, zones, codec, identity, cookies, tsig, limiter).ConfigureAwait(false);
    }

    private ZoneBundleAdapter CreateCodec(ControlConfiguration configuration, DnsServiceSecrets secrets)
    {
        Dictionary<DnsName, DnssecSigningPolicy> policies = [];
        foreach (var scope in configuration.Zones)
        {
            if (scope.SigningKeySecret is null)
            {
                if (scope.SignatureLifetimeSeconds != 604_800 || scope.DnskeyTtl != 3600 || scope.RenewBeforeSeconds is not null)
                    throw new InvalidDataException("Signing policy requires a private key.");
                continue;
            }
            var bytes = secrets.Bytes(scope.SigningKeySecret, 4096);
            try
            {
                var key = EcdsaP256DnssecSigningKey.ImportPkcs8(bytes);
                dnssecKeys.Add(key);
                var origin = DnsName.Parse(scope.Origin);
                if (origin.ToWire().AsSpan().StartsWith(new byte[] { 1, (byte)'*' }))
                    throw new InvalidDataException("Signed serving excludes a literal wildcard apex.");
                policies.Add(origin, new DnssecSigningPolicy(key, scope.SignatureLifetimeSeconds, scope.DnskeyTtl));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        return policies.Count == 0 ? new ZoneBundleAdapter()
            : new ZoneBundleAdapter(new DnssecZoneSigningService(policies, new EcdsaP256DnssecVerifier(), TimeProvider.System));
    }

    private async ValueTask InitializeControllerAsync(ControlConfiguration configuration, Dictionary<Guid, DnsName> zones, ZoneBundleAdapter codec, P256PublicationAuthenticator identity)
    {
        if (configuration.ConnectionStringSecret is null || configuration.PublicationSocket is null || configuration.Grants is not { Length: > 0 and <= 64 })
            throw new InvalidDataException("Controller database, target and management grants are required.");
        var grants = configuration.Grants.Select(CreateGrant).ToArray();
        if (grants.Any(grant => !zones.TryGetValue(grant.ZoneId, out var origin) || !origin.Equals(grant.Origin)))
            throw new InvalidDataException("Management grants exceed the publisher scope.");
        var authorization = managementAuthorizer ?? throw new InvalidDataException("ControlPreflightMissing");
        store = new PostgresControlPlaneStore(connectionString ?? throw new InvalidDataException("ControlPreflightMissing"));
        await store.InitializeAsync(configuration.Epoch, CancellationToken.None).ConfigureAwait(false);
        Management = new ZoneManagementApplication(store, authorization, codec, configuration.TargetNode, new ZoneMasterFileAdapter());
        client = new UnixControlClient(configuration.PublicationSocket);
        publisher = new OutboxPublisher(store, identity, client);
        if (renewalScopes.Length > 0)
            resigning = new ZoneResigningApplication(store, codec, new EcdsaP256DnssecVerifier(), TimeProvider.System, configuration.TargetNode, renewalScopes);
    }

    private static ManagementGrant CreateGrant(GrantConfiguration grant)
    {
        var actions = grant.Actions ?? throw new InvalidDataException("SecretGrantActionsMissing");
        var scopes = grant.RecordScopes ?? throw new InvalidDataException("SecretGrantScopesMissing");
        if (scopes.Length > 64 || actions.Length is 0 or > 6)
            throw new InvalidDataException("Invalid management grant bounds.");
        return new ManagementGrant(grant.TenantId, grant.ZoneId, DnsName.Parse(grant.Origin), grant.Actor, grant.Expires, grant.CredentialHash)
        {
            Profile = grant.Profile,
            Actions = actions,
            RecordScopes = [.. scopes.Select(scope => new ManagementRecordScope(DnsName.Parse(scope.Owner), scope.Type))],
        };
    }

    private async ValueTask InitializeReplicaAsync(ApplicationSettings settings, ControlConfiguration configuration, FileZoneSnapshotStore snapshots, Dictionary<Guid, DnsName> zones, ZoneBundleAdapter codec, P256PublicationAuthenticator identity, IDnsCookieService? cookies, ITsigService? tsig, IDnsResponseLimiter? limiter)
    {
        if (configuration.ConnectionStringSecret is not null || configuration.PublicationSocket is not null || configuration.Grants is { Length: > 0 })
            throw new InvalidDataException("A serving replica cannot take controller configuration.");
        journal = new FilePublicationJournal(settings.StateDirectory + ".publications");
        Authority = new AuthoritativeApplication(new DnsMessageCodecAdapter(), settings.NodeId, cookies, tsig, limiter);
        Publication = await ZonePublicationApplication.OpenAsync(snapshots, journal, identity, codec, Authority, settings.NodeId, zones.Keys,
            new EcdsaP256DnssecVerifier(), TimeProvider.System, CancellationToken.None).ConfigureAwait(false);
    }

    internal async Task PublishAsync(ILogger logger, CancellationToken cancellationToken)
    {
        if (publisher is null)
            return;
        long? lastScan = null;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var sample = TimeProvider.System.GetTimestamp();
                if (resigning is not null && (lastScan is null || TimeProvider.System.GetElapsedTime(lastScan.Value, sample) >= signingScan))
                {
                    lastScan = sample;
                    await RenewAsync(logger, cancellationToken).ConfigureAwait(false);
                }
                if (await publisher.DispatchOneAsync(cancellationToken).ConfigureAwait(false))
                    continue;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is RpcException or IOException or InvalidOperationException or NpgsqlException or CryptographicException)
            {
                if (logger.IsEnabled(LogLevel.Information))
                    ControlLogs.Pending(logger, "transport-or-storage");
            }
            try
            {
                await Task.Delay(dispatchInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    private async Task RenewAsync(ILogger logger, CancellationToken cancellationToken)
    {
        foreach (var scope in renewalScopes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (await resigning!.ResignAsync(scope.ZoneId, cancellationToken).ConfigureAwait(false) && logger.IsEnabled(LogLevel.Information))
                    ControlLogs.Renewed(logger, scope.ZoneId);
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException or NpgsqlException or CryptographicException or FormatException or ArgumentException or OverflowException)
            {
                if (logger.IsEnabled(LogLevel.Information))
                    ControlLogs.RenewalPending(logger, scope.ZoneId);
            }
        }
    }

    private readonly Lock disposalSync = new();
    private Task? disposal;
    private FileZoneSnapshotStore? snapshots;

    internal ControlRuntime() { }

    // Direct owned composition is also used by the maintained shutdown control.
    internal ControlRuntime(FileZoneSnapshotStore snapshots, ZonePublicationApplication publication)
    {
        this.snapshots = snapshots;
        Publication = publication;
    }

    internal FileZoneSnapshotStore OpenSnapshots(string directory)
    {
        lock (disposalSync)
        {
            ObjectDisposedException.ThrowIf(disposal is not null, this);
            if (snapshots is not null) throw new InvalidOperationException("SnapshotOwnershipAlreadyTransferred");
            snapshots = new FileZoneSnapshotStore(directory);
            return snapshots;
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (disposalSync) return new ValueTask(disposal ??= CloseAsync());
    }

    private async Task CloseAsync()
    {
        List<Exception> failures = [];
        // First join the entire publication continuation, not merely its last
        // registered snapshot operation. Only then close snapshot admission.
        await CaptureAsync(ClosePublicationAsync(), failures).ConfigureAwait(false);
        await CaptureAsync(CloseSnapshotsAsync(), failures).ConfigureAwait(false);
        await CaptureAsync(CloseTransportAsync(), failures).ConfigureAwait(false);
        await CaptureAsync(CloseStoreAsync(), failures).ConfigureAwait(false);
        foreach (var key in dnssecKeys)
            await CaptureAsync(CloseKeyAsync(key), failures).ConfigureAwait(false);
        if (failures.Count == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count > 1) throw new AggregateException(failures);
    }

    private async Task ClosePublicationAsync()
    {
        if (Publication is not null) await Publication.DisposeAsync().ConfigureAwait(false);
    }

    private async Task CloseSnapshotsAsync()
    {
        if (snapshots is not null) await snapshots.DisposeAsync().ConfigureAwait(false);
    }

    private async Task CloseStoreAsync()
    {
        if (store is not null) await store.DisposeAsync().ConfigureAwait(false);
    }

    private async Task CloseTransportAsync()
    {
        // Each independently acquired native owner is attempted even if another
        // terminal disposal faults. Native keys retire after actual store drain.
        List<Exception> failures = [];
        await CaptureAsync(CloseClientAsync(), failures).ConfigureAwait(false);
        await CaptureAsync(CloseJournalAsync(), failures).ConfigureAwait(false);
        await CaptureAsync(CloseAuthenticatorAsync(), failures).ConfigureAwait(false);
        if (failures.Count > 0) throw new AggregateException(failures);
    }

    private async Task CloseClientAsync() { await Task.CompletedTask.ConfigureAwait(false); client?.Dispose(); }
    private async Task CloseJournalAsync() { await Task.CompletedTask.ConfigureAwait(false); journal?.Dispose(); }
    private async Task CloseAuthenticatorAsync() { await Task.CompletedTask.ConfigureAwait(false); authenticator?.Dispose(); }
    private static async Task CloseKeyAsync(EcdsaP256DnssecSigningKey key) { await Task.CompletedTask.ConfigureAwait(false); key.Dispose(); }

    private static async Task CaptureAsync(Task task, List<Exception> failures)
    {
        try { await task.WaitAsync(CancellationToken.None).ConfigureAwait(false); }
        catch (Exception error) when (task.IsFaulted || task.IsCanceled)
        {
            if (task.Exception is { InnerExceptions.Count: 1 } single) failures.Add(single.InnerExceptions[0]);
            else failures.Add(task.Exception ?? error);
        }
    }
}
