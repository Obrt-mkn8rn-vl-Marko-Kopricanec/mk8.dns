using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

public static class QueryHostingExtensions
{
    public const int MaximumExchangeBytes = 66_047;

    public static IServiceCollection AddAuthoritativeQuery(this IServiceCollection services, IDnsExchange source)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(source);
        services.AddGrpc().AddServiceOptions<AuthoritativeQueryService>(options =>
        {
            options.MaxReceiveMessageSize = MaximumExchangeBytes;
            options.MaxSendMessageSize = MaximumExchangeBytes;
            options.EnableDetailedErrors = false;
        });
        services.AddSingleton(source);
        services.AddSingleton(provider => new AuthoritativeQueryService(provider.GetRequiredService<IDnsExchange>()));
        return services;
    }

    public static IEndpointRouteBuilder MapAuthoritativeQuery(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        endpoints.MapGrpcService<AuthoritativeQueryService>();
        return endpoints;
    }
}
