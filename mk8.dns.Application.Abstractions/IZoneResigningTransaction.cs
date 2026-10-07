using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IZoneResigningTransaction : IControlTransaction
{
    ValueTask<ZoneOperation?> ReadGenerationAsync(Guid tenantId, Guid zoneId, long revision, CancellationToken cancellationToken);
    ValueTask<bool> HasPendingAsync(Guid zoneId, CancellationToken cancellationToken);
}
