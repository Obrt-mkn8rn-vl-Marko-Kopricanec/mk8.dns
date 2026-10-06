using Grpc.Core;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Presentation;
using Mk8.Dns.Transport;

namespace Mk8.Dns.Gateway;

internal static class ManagementGatewayHost
{
    internal static async Task RunAsync(GatewaySettings settings)
    {
        using var lease = new PrivateUnixSocket(settings.ManagementSocketPath!);
        using var client = new UnixControlClient(settings.SocketPath);
        using var status = new UnixApplicationClient(settings.SocketPath);
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.Logging.AddJsonConsole();
        builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
        builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(20));
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false;
            options.Limits.MaxRequestBodySize = ManagementHttpProtocol.MaximumRequestBytes;
            options.Limits.MaxRequestHeadersTotalSize = 4096;
            options.Limits.MaxRequestHeaderCount = 32;
            options.Limits.MaxRequestLineSize = 2048;
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
            options.Limits.MaxConcurrentConnections = 16;
            options.ListenUnixSocket(lease.Path, endpoint => endpoint.Protocols = HttpProtocols.Http1);
        });
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
                using var stop = gateway.Lifetime.ApplicationStopping.Register(() => stopped.TrySetResult());
                try
                {
                    await gateway.StartAsync().ConfigureAwait(false);
                    lease.SetSocketPermissions();
                    await stopped.Task.ConfigureAwait(false);
                }
                finally
                {
                    await api.DisposeAsync().ConfigureAwait(false);
                    await gateway.StopAsync().ConfigureAwait(false);
                }
            }
        }
    }
}
