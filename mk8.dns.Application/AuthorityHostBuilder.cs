using Microsoft.AspNetCore.Server.Kestrel.Core;
using Mk8.Dns.Configuration;
using Mk8.Dns.Transport;

namespace Mk8.Dns.Application;

internal static class AuthorityHostBuilder
{
    internal static WebApplicationBuilder Create(PrivateUnixSocket socket, ServiceHostPolicy policy, long maximumRequestBytes, int maximumStreams)
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
        {
            Args = [],
            EnvironmentName = "Production",
            ContentRootPath = AppContext.BaseDirectory,
        });
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
            options.Limits.MaxRequestHeadersTotalSize = policy.HeaderBytes;
            options.Limits.MaxRequestHeaderCount = policy.HeaderCount;
            options.Limits.MaxRequestLineSize = policy.RequestLineBytes;
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(policy.HeaderTimeoutSeconds);
            options.Limits.MaxConcurrentConnections = policy.Connections;
            options.Limits.MaxRequestBodySize = maximumRequestBytes;
            options.Limits.Http2.MaxStreamsPerConnection = maximumStreams;
            options.ListenUnixSocket(socket.Path, endpoint => endpoint.Protocols = HttpProtocols.Http2);
        });
        return builder;
    }
}
