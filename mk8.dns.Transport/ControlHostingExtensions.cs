using System.Text.Json;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

public static class ControlHostingExtensions
{
    public const int MaximumManagementBytes = 2_500_000;
    public const int MaximumPublicationBytes = 1_500_000;

    public static IServiceCollection AddZoneManagement(this IServiceCollection services, IZoneManagement source)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(source);
        services.AddGrpc().AddServiceOptions<ManagementService>(options =>
        {
            options.MaxReceiveMessageSize = MaximumManagementBytes;
            options.MaxSendMessageSize = MaximumManagementBytes;
            options.EnableDetailedErrors = false;
        });
        services.AddSingleton(source);
        services.AddSingleton(provider => new ManagementService(provider.GetRequiredService<IZoneManagement>()));
        return services;
    }

    public static IServiceCollection AddZonePublication(this IServiceCollection services, IZonePublication source)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(source);
        services.AddGrpc().AddServiceOptions<PublicationService>(options =>
        {
            options.MaxReceiveMessageSize = MaximumPublicationBytes;
            options.MaxSendMessageSize = ProtocolVersion.MaximumMessageBytes;
            options.EnableDetailedErrors = false;
        });
        services.AddSingleton(source);
        services.AddSingleton(provider => new PublicationService(provider.GetRequiredService<IZonePublication>()));
        return services;
    }

    public static IEndpointRouteBuilder MapZoneManagement(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        endpoints.MapGrpcService<ManagementService>();
        return endpoints;
    }

    public static IEndpointRouteBuilder MapZonePublication(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        endpoints.MapGrpcService<PublicationService>();
        return endpoints;
    }
}
