using Microsoft.AspNetCore.Server.Kestrel.Core;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;

var settings = ApplicationSettings.Parse(args);
using var socket = new PrivateUnixSocket(settings.SocketPath);
var snapshots = new FileZoneSnapshotStore(settings.StateDirectory);
await using var snapshotLifetime = snapshots.ConfigureAwait(false);

var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
builder.Configuration.Sources.Clear();
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = ProtocolVersion.MaximumMessageBytes + 5;
    options.Limits.Http2.MaxStreamsPerConnection = 16;
    options.ListenUnixSocket(socket.Path, endpoint => endpoint.Protocols = HttpProtocols.Http2);
});
builder.Services.AddApplicationProbe(new ApplicationStatusSource(snapshots, settings.NodeId, settings.Role));

var application = builder.Build();
await using (application.ConfigureAwait(false))
{
    application.MapApplicationProbe();
    await application.StartAsync().ConfigureAwait(false);
    socket.SetSocketPermissions();
    await application.WaitForShutdownAsync().ConfigureAwait(false);
}
