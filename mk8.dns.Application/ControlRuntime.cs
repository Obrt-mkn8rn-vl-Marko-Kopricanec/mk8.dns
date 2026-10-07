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
using Mk8.Dns.Transport;

namespace Mk8.Dns.Application;

internal sealed class ControlRuntime : IAsyncDisposable
{
    private PostgresControlPlaneStore? store;
    private P256PublicationAuthenticator? authenticator;
    private FilePublicationJournal? journal;
    private UnixControlClient? client;
    private OutboxPublisher? publisher;
    internal AuthoritativeApplication? Authority { get; private set; }
    internal ZoneManagementApplication? Management { get; private set; }
    internal ZonePublicationApplication? Publication { get; private set; }

    internal async ValueTask InitializeAsync(ApplicationSettings settings, FileZoneSnapshotStore snapshots, IDnsCookieService? cookies, ITsigService? tsig)
    {
        if (settings.ControlFile is null)
            return;
        var configuration = JsonSerializer.Deserialize(PrivateFile.Read(settings.ControlFile, 65_536), ControlConfigurationContext.Default.ControlConfiguration)
            ?? throw new InvalidDataException("Control configuration is empty.");
        if (configuration.Zones is not { Length: > 0 and <= 64 } || configuration.KeyFile is null || configuration.TargetNode is null)
            throw new InvalidDataException("Publisher scope and key are required.");
        var zones = configuration.Zones.ToDictionary(zone => zone.ZoneId, zone => DnsName.Parse(zone.Origin));
        var controller = string.Equals(settings.Role, "controller", StringComparison.Ordinal);
        if (!controller && !string.Equals(configuration.TargetNode, settings.NodeId, StringComparison.Ordinal))
            throw new InvalidDataException("Publisher trust targets a different replica.");
        var identity = new P256PublicationAuthenticator(configuration.Epoch, configuration.TargetNode, zones, Encoding.UTF8.GetString(PrivateFile.Read(configuration.KeyFile, 4096)), controller);
        authenticator = identity;
        var codec = new ZoneBundleAdapter();
        if (controller)
            await InitializeControllerAsync(configuration, zones, codec, identity).ConfigureAwait(false);
        else
            await InitializeReplicaAsync(settings, configuration, snapshots, zones, codec, identity, cookies, tsig).ConfigureAwait(false);
    }

    private async ValueTask InitializeControllerAsync(ControlConfiguration configuration, Dictionary<Guid, DnsName> zones, ZoneBundleAdapter codec, P256PublicationAuthenticator identity)
    {
        if (configuration.ConnectionStringFile is null || configuration.PublicationSocket is null || configuration.Grants is not { Length: > 0 and <= 64 })
            throw new InvalidDataException("Controller database, target and management grants are required.");
        var grants = configuration.Grants.Select(CreateGrant).ToArray();
        if (grants.Any(grant => !zones.TryGetValue(grant.ZoneId, out var origin) || !origin.Equals(grant.Origin)))
            throw new InvalidDataException("Management grants exceed the publisher scope.");
        store = new PostgresControlPlaneStore(Encoding.UTF8.GetString(PrivateFile.Read(configuration.ConnectionStringFile, 4096)));
        await store.InitializeAsync(configuration.Epoch, CancellationToken.None).ConfigureAwait(false);
        Management = new ZoneManagementApplication(store, new ScopedManagementAuthorizer(grants, TimeProvider.System), codec, configuration.TargetNode, new ZoneMasterFileAdapter());
        client = new UnixControlClient(configuration.PublicationSocket);
        publisher = new OutboxPublisher(store, identity, client);
    }

    private static ManagementGrant CreateGrant(GrantConfiguration grant)
    {
        var actions = grant.Actions ?? (grant.Profile is "zone" ? ["edit", "patch", "read", "status"] : Array.Empty<string>());
        var scopes = grant.RecordScopes ?? Array.Empty<RecordScopeConfiguration>();
        if (scopes.Length > 64 || actions.Length is 0 or > 6)
            throw new InvalidDataException("Invalid management grant bounds.");
        return new ManagementGrant(grant.TenantId, grant.ZoneId, DnsName.Parse(grant.Origin), grant.Actor, grant.Expires, grant.CredentialHash)
        {
            Profile = grant.Profile,
            Actions = actions,
            RecordScopes = scopes.Select(scope => new ManagementRecordScope(DnsName.Parse(scope.Owner), scope.Type)).ToArray(),
        };
    }

    private async ValueTask InitializeReplicaAsync(ApplicationSettings settings, ControlConfiguration configuration, FileZoneSnapshotStore snapshots, Dictionary<Guid, DnsName> zones, ZoneBundleAdapter codec, P256PublicationAuthenticator identity, IDnsCookieService? cookies, ITsigService? tsig)
    {
        if (configuration.ConnectionStringFile is not null || configuration.PublicationSocket is not null || configuration.Grants is { Length: > 0 })
            throw new InvalidDataException("A serving replica cannot take controller configuration.");
        journal = new FilePublicationJournal(settings.StateDirectory + ".publications");
        Authority = new AuthoritativeApplication(new DnsMessageCodecAdapter(), settings.NodeId, cookies, tsig);
        Publication = await ZonePublicationApplication.OpenAsync(snapshots, journal, identity, codec, Authority, settings.NodeId, zones.Keys, CancellationToken.None).ConfigureAwait(false);
    }

    internal async Task PublishAsync(ILogger logger, CancellationToken cancellationToken)
    {
        if (publisher is null)
            return;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
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
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Publication is not null)
            await Publication.DisposeAsync().ConfigureAwait(false);
        client?.Dispose();
        journal?.Dispose();
        authenticator?.Dispose();
        if (store is not null)
            await store.DisposeAsync().ConfigureAwait(false);
    }
}
