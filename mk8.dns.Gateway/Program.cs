using System.Net;
using Grpc.Core;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Gateway;
using Mk8.Dns.Presentation;
using Mk8.Dns.Transport;

var settings = GatewaySettings.Parse(args);
if (settings.Role == GatewayRole.Management)
{
    await ManagementGatewayHost.RunAsync(settings).ConfigureAwait(false);
    return;
}
using var client = new UnixApplicationClient(settings.SocketPath);
using var queries = new UnixDnsClient(settings.SocketPath);
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
    gateway.MapGet("/health/ready", async (CancellationToken cancellationToken) =>
    {
        if (settings.DnsEndpoint is null)
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        try
        {
            var status = await client.GetStatusAsync(ProtocolVersion.Current, cancellationToken).ConfigureAwait(false);
            return Results.StatusCode(status.DnsReady ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
        }
        catch (RpcException)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    });
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
    if (settings.DnsEndpoint is null)
        await gateway.RunAsync().ConfigureAwait(false);
    else
        await RunDnsGatewayAsync(gateway, settings, queries).ConfigureAwait(false);
}

static async Task RunDnsGatewayAsync(WebApplication gateway, GatewaySettings settings, IDnsExchange queries)
{
    using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(gateway.Lifetime.ApplicationStopping);
    var listener = new AuthoritativeListener(settings.DnsEndpoint!, queries);
    var dns = listener.RunAsync(lifetime.Token);
    try
    {
        if (dns.IsCompleted)
            await dns.ConfigureAwait(false);
        await gateway.StartAsync().ConfigureAwait(false);
        var shutdown = gateway.WaitForShutdownAsync();
        var finished = await Task.WhenAny(dns, shutdown).ConfigureAwait(false);
        await finished.ConfigureAwait(false);
    }
    catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
    finally
    {
        await lifetime.CancelAsync().ConfigureAwait(false);
        await gateway.StopAsync().ConfigureAwait(false);
        try
        {
            await dns.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
    }
}
