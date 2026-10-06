using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IPublicationJournal
{
    ValueTask SaveAsync(string id, ReadOnlyMemory<byte> body, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken);
    ValueTask<PublicationRequest> ReadAsync(string id, CancellationToken cancellationToken);
    ValueTask RecordActivationAsync(string id, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken);
    ValueTask<IReadOnlyList<string>> ReadActivatedIdsAsync(CancellationToken cancellationToken);
    ValueTask<byte[]> ReadActivationSignatureAsync(string id, CancellationToken cancellationToken);
}
