using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

public static class ProbeHostingExtensions
{
    public static IServiceCollection AddApplicationProbe(this IServiceCollection services, IApplicationStatusSource source)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(source);
        services.AddGrpc(options =>
        {
            options.MaxReceiveMessageSize = ProtocolVersion.MaximumMessageBytes;
            options.MaxSendMessageSize = ProtocolVersion.MaximumMessageBytes;
            options.EnableDetailedErrors = false;
        });
        services.AddSingleton(source);
        services.AddSingleton(provider => new ApplicationProbeService(provider.GetRequiredService<IApplicationStatusSource>()));
        return services;
    }

    public static IEndpointRouteBuilder MapApplicationProbe(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        endpoints.MapGrpcService<ApplicationProbeService>();
        return endpoints;
    }
}
