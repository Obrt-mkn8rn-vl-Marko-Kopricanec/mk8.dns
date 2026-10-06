using Microsoft.AspNetCore.Server.Kestrel.Core;
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
using var socket = new PrivateUnixSocket(settings.SocketPath);
var snapshots = new FileZoneSnapshotStore(settings.StateDirectory);
await using var snapshotLifetime = snapshots.ConfigureAwait(false);
AuthoritativeApplication? authority = null;
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
    authority = new AuthoritativeApplication(new AuthoritativeCatalog(zones), new DnsMessageCodecAdapter(), settings.NodeId);
}

var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
builder.Configuration.Sources.Clear();
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = (authority is null ? ProtocolVersion.MaximumMessageBytes : QueryHostingExtensions.MaximumExchangeBytes) + 5;
    options.Limits.Http2.MaxStreamsPerConnection = 16;
    options.ListenUnixSocket(socket.Path, endpoint => endpoint.Protocols = HttpProtocols.Http2);
});
IApplicationStatusSource statusSource = authority is null ? new ApplicationStatusSource(snapshots, settings.NodeId, settings.Role) : authority;
builder.Services.AddApplicationProbe(statusSource);
if (authority is not null)
    builder.Services.AddAuthoritativeQuery(authority);

var application = builder.Build();
await using (application.ConfigureAwait(false))
{
    application.MapApplicationProbe();
    if (authority is not null)
        application.MapAuthoritativeQuery();
    await application.StartAsync().ConfigureAwait(false);
    socket.SetSocketPermissions();
    await application.WaitForShutdownAsync().ConfigureAwait(false);
}
