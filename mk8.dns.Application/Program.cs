using Microsoft.AspNetCore.Server.Kestrel.Core;
using Mk8.Dns.Application;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Transport;
using Mk8.Dns.Wire;

var settings = ApplicationSettings.Parse(args);
using var cookies = string.Equals(settings.Role, "authoritative-replica", StringComparison.Ordinal) ? CookieSecrets.Load(settings) : null;
using var socket = new PrivateUnixSocket(settings.SocketPath);
var snapshots = new FileZoneSnapshotStore(settings.StateDirectory);
await using var snapshotLifetime = snapshots.ConfigureAwait(false);
var control = new ControlRuntime();
await using var controlLifetime = control.ConfigureAwait(false);
await control.InitializeAsync(settings, snapshots, cookies).ConfigureAwait(false);
AuthoritativeApplication? authority = control.Authority;
if (settings.ZoneIds.Count != 0)
{
    _ = await snapshots.CountActiveAsync(CancellationToken.None).ConfigureAwait(false);
    List<AuthoritativeZone> zones = [];
    foreach (var id in settings.ZoneIds)
    {
        var snapshot = await snapshots.ReadActiveAsync(id, CancellationToken.None).ConfigureAwait(false)
            ?? throw new InvalidDataException("A configured authoritative zone has no active generation.");
        zones.Add(ZoneBundleCodec.Decode(snapshot));
    }
    authority = new AuthoritativeApplication(new AuthoritativeCatalog(zones), new DnsMessageCodecAdapter(), settings.NodeId, cookies);
}

var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
builder.Configuration.Sources.Clear();
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = (control.Management is not null ? ControlHostingExtensions.MaximumManagementBytes : authority is null ? ProtocolVersion.MaximumMessageBytes : QueryHostingExtensions.MaximumExchangeBytes) + 5;
    options.Limits.Http2.MaxStreamsPerConnection = 16;
    options.ListenUnixSocket(socket.Path, endpoint => endpoint.Protocols = HttpProtocols.Http2);
});
IApplicationStatusSource statusSource = authority is null ? new ApplicationStatusSource(snapshots, settings.NodeId, settings.Role) : authority;
builder.Services.AddApplicationProbe(statusSource);
if (authority is not null)
    builder.Services.AddAuthoritativeQuery(authority);
if (control.Management is not null)
    builder.Services.AddZoneManagement(control.Management);

var application = builder.Build();
await using (application.ConfigureAwait(false))
{
    application.MapApplicationProbe();
    if (authority is not null)
        application.MapAuthoritativeQuery();
    if (control.Management is not null)
        application.MapZoneManagement();
    using var publicationSocket = settings.PublicationSocket is null ? null : new PrivateUnixSocket(settings.PublicationSocket);
    WebApplication? publicationHost = null;
    using var shutdown = new CancellationTokenSource();
    Task publishing = Task.CompletedTask;
    try
    {
        if (publicationSocket is not null && control.Publication is not null)
        {
            var publicationBuilder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
            publicationBuilder.Configuration.Sources.Clear();
            publicationBuilder.Logging.ClearProviders();
            publicationBuilder.Logging.AddJsonConsole();
            publicationBuilder.WebHost.ConfigureKestrel(options =>
            {
                options.AddServerHeader = false;
                options.Limits.MaxRequestBodySize = ControlHostingExtensions.MaximumPublicationBytes + 5;
                options.Limits.Http2.MaxStreamsPerConnection = 2;
                options.ListenUnixSocket(publicationSocket.Path, endpoint => endpoint.Protocols = HttpProtocols.Http2);
            });
            publicationBuilder.Services.AddZonePublication(control.Publication);
            publicationHost = publicationBuilder.Build();
            publicationHost.MapZonePublication();
            await publicationHost.StartAsync().ConfigureAwait(false);
            publicationSocket.SetSocketPermissions();
        }
        await application.StartAsync().ConfigureAwait(false);
        socket.SetSocketPermissions();
        publishing = PublishAndStopOnFailureAsync(control, application.Logger, application.Lifetime, shutdown.Token);
        await application.WaitForShutdownAsync().ConfigureAwait(false);
    }
    finally
    {
        await shutdown.CancelAsync().ConfigureAwait(false);
        if (publicationHost is not null)
        {
            await publicationHost.StopAsync().ConfigureAwait(false);
            await publicationHost.DisposeAsync().ConfigureAwait(false);
        }
        await publishing.WaitAsync(CancellationToken.None).ConfigureAwait(false);
    }
}

static async Task PublishAndStopOnFailureAsync(ControlRuntime control, ILogger logger, IHostApplicationLifetime lifetime, CancellationToken cancellationToken)
{
    try
    {
        await control.PublishAsync(logger, cancellationToken).ConfigureAwait(false);
    }
    catch
    {
        lifetime.StopApplication();
        throw;
    }
}
