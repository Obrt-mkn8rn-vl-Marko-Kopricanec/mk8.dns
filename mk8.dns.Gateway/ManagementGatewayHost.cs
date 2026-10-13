using Grpc.Core;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Presentation;
using Mk8.Dns.Transport;

namespace Mk8.Dns.Gateway;

internal static class ManagementGatewayHost
{
    internal static async Task RunAsync(GatewaySettings settings, ServiceHostPolicy policy)
    {
        if (policy.ShutdownSeconds > 20) throw new InvalidDataException("SecretManagementShutdownBounds");
        using var lease = new PrivateUnixSocket(settings.ManagementSocketPath!);
        using var client = new UnixControlClient(settings.SocketPath);
        using var status = new UnixApplicationClient(settings.SocketPath);
        var builder = CreateBuilder(lease, policy);
        var gateway = builder.Build();
        await using (gateway.ConfigureAwait(false))
        {
            var api = new ManagementHttpApi(client);
            await using (api.ConfigureAwait(false))
            {
                api.Map(gateway);
                gateway.MapGet("/health/live", () => Results.StatusCode(200));
                gateway.MapGet("/health/ready", async (CancellationToken token) =>
                {
                    try
                    {
                        var probe = await status.GetStatusAsync(ProtocolVersion.Current, token).ConfigureAwait(false);
                        return Results.StatusCode(probe.Role is "controller" ? 200 : 503);
                    }
                    catch (RpcException)
                    {
                        return Results.StatusCode(503);
                    }
                });
                var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var stop = gateway.Lifetime.ApplicationStopping.Register(() => stopped.TrySetResult());
                await using var stopLifetime = stop.ConfigureAwait(false);
                try
                {
                    await gateway.StartAsync(CancellationToken.None).ConfigureAwait(false);
                    lease.SetSocketPermissions();
                    await stopped.Task.ConfigureAwait(false);
                }
                finally
                {
                    await api.DisposeAsync().ConfigureAwait(false);
                    await gateway.StopAsync(CancellationToken.None).ConfigureAwait(false);
                }
            }
        }
    }
    private static WebApplicationBuilder CreateBuilder(PrivateUnixSocket lease, ServiceHostPolicy policy)
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions { Args = [], EnvironmentName = "Production", ContentRootPath = AppContext.BaseDirectory });
        builder.Configuration.Sources.Clear();
        builder.WebHost.UseKestrelCore();
        builder.Services.AddRouting();
        builder.Host.UseConsoleLifetime();
        builder.Configuration.AddInMemoryCollection([new KeyValuePair<string, string?>(WebHostDefaults.PreventHostingStartupKey, "true")]);
        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole();
        builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
        builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(policy.ShutdownSeconds));
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false;
            options.Limits.MaxRequestBodySize = ManagementHttpProtocol.MaximumRequestBytes;
            options.Limits.MaxRequestHeadersTotalSize = policy.HeaderBytes;
            options.Limits.MaxRequestHeaderCount = policy.HeaderCount;
            options.Limits.MaxRequestLineSize = policy.RequestLineBytes;
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(policy.HeaderTimeoutSeconds);
            options.Limits.MaxConcurrentConnections = policy.Connections;
            options.ListenUnixSocket(lease.Path, endpoint => endpoint.Protocols = HttpProtocols.Http1);
        });
        return builder;
    }

}
