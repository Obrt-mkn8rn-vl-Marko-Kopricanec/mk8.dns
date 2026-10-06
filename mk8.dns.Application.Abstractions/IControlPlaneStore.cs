using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IControlPlaneStore
{
    ValueTask<IControlTransaction> BeginAsync(CancellationToken cancellationToken);
    ValueTask<ZoneOperation?> ReadPendingAsync(CancellationToken cancellationToken);
    ValueTask MarkActivatedAsync(ZoneOperation operation, PublicationReply receipt, CancellationToken cancellationToken);
}
