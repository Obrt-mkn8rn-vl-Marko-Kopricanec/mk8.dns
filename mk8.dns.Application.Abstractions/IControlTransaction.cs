using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IControlTransaction : IAsyncDisposable
{
    ValueTask<ZoneOperation?> ReadOperationAsync(Guid tenantId, Guid operationId, CancellationToken cancellationToken);
    ValueTask<ZoneSnapshot?> ReadZoneAsync(Guid tenantId, Guid zoneId, CancellationToken cancellationToken);
    ValueTask<IReadOnlyList<ZoneOwnership>> ReadOwnershipAsync(CancellationToken cancellationToken);
    ValueTask AppendAsync(ZoneOperation operation, CancellationToken cancellationToken);
    ValueTask CommitAsync(CancellationToken cancellationToken);
}
