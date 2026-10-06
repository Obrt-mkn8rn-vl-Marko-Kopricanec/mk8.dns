using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IZoneSnapshotStore
{
    ValueTask ActivateAsync(ZoneSnapshot snapshot, CancellationToken cancellationToken);
    ValueTask<ZoneSnapshot?> ReadActiveAsync(Guid zoneId, CancellationToken cancellationToken);
    ValueTask<uint> CountActiveAsync(CancellationToken cancellationToken);
}
