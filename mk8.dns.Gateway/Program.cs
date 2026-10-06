using System.Net;
using Grpc.Core;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;

var settings = GatewaySettings.Parse(args);
using var client = new UnixApplicationClient(settings.SocketPath);
var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
builder.Configuration.Sources.Clear();
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 0;
    options.Limits.MaxRequestHeadersTotalSize = 4096;
    options.Listen(IPAddress.Loopback, settings.HealthPort);
});

var gateway = builder.Build();
await using (gateway.ConfigureAwait(false))
{
    gateway.MapGet("/health/live", () => Results.StatusCode(StatusCodes.Status200OK));
    gateway.MapGet("/health/ready", () => Results.StatusCode(StatusCodes.Status503ServiceUnavailable));
    gateway.MapGet("/health/application", async (CancellationToken cancellationToken) =>
    {
        try
        {
            var status = await client.GetStatusAsync(ProtocolVersion.Current, cancellationToken).ConfigureAwait(false);
            return Results.Json(new
            {
                protocolVersion = status.ProtocolVersion,
                nodeId = status.NodeId,
                role = status.Role,
                dnsReady = status.DnsReady,
                activeSnapshots = status.ActiveSnapshots,
            });
        }
        catch (RpcException)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    });
    await gateway.RunAsync().ConfigureAwait(false);
}
