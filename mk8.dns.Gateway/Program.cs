using System.Net;
using Grpc.Core;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Gateway;
using Mk8.Dns.Presentation;
using Mk8.Dns.Transport;

if (args.Length != 0) throw new ArgumentException("ServiceArgumentsForbidden", nameof(args));
var secrets = await DnsServiceSecrets.LoadAsync("Gateway", CancellationToken.None).ConfigureAwait(false);
var settings = GatewaySettings.FromSecrets(secrets);
PrivateUnixSocket.ValidatePath(settings.SocketPath);
if (settings.ManagementSocketPath is { } managementPath) PrivateUnixSocket.ValidatePath(managementPath);
var policy = ServiceHostPolicy.FromSecrets(secrets);
var dnsPolicy = GatewayDnsPolicy.FromSecrets(secrets);
if (settings.Role == GatewayRole.Management)
{
    await ManagementGatewayHost.RunAsync(settings, policy).ConfigureAwait(false);
    return;
}
using var client = new UnixApplicationClient(settings.SocketPath);
using var queries = new UnixDnsClient(settings.SocketPath);
var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions { Args = [], EnvironmentName = "Production", ContentRootPath = AppContext.BaseDirectory });
builder.Configuration.Sources.Clear();
builder.WebHost.UseKestrelCore();
builder.Services.AddRouting();
builder.Host.UseConsoleLifetime();
builder.Configuration.AddInMemoryCollection([new KeyValuePair<string, string?>(WebHostDefaults.PreventHostingStartupKey, "true")]);
builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(policy.ShutdownSeconds));
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole();
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 0;
    options.Limits.MaxRequestHeadersTotalSize = policy.HeaderBytes;
    options.Limits.MaxRequestHeaderCount = policy.HeaderCount;
    options.Limits.MaxRequestLineSize = policy.RequestLineBytes;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(policy.HeaderTimeoutSeconds);
    options.Limits.MaxConcurrentConnections = policy.Connections;
    options.Listen(IPAddress.Loopback, settings.HealthPort);
});

var gateway = builder.Build();
await ServiceExecution.RunAsync(async () =>
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
    var listener = settings.DnsEndpoint is null ? null : new AuthoritativeListener(settings.DnsEndpoint, queries,
        dnsPolicy.TcpConnections, dnsPolicy.MessagesPerConnection, TimeSpan.FromMilliseconds(dnsPolicy.FrameTimeoutMilliseconds));
    await QueryHostExecution.RunAsync(gateway, listener is null ? null : listener.RunAsync).ConfigureAwait(false);
}, () => gateway.DisposeAsync().AsTask()).ConfigureAwait(false);
