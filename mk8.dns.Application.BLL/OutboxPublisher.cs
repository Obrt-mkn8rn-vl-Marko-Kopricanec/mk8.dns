using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Application.BLL;

public sealed class OutboxPublisher(IControlPlaneStore store, IPublicationAuthenticator authenticator, IZonePublication replica)
{
    public async ValueTask<bool> DispatchOneAsync(CancellationToken cancellationToken)
    {
        var operation = await store.ReadPendingAsync(cancellationToken).ConfigureAwait(false);
        if (operation is null)
            return false;
        var body = authenticator.CreateBody(operation.Snapshot);
        var signature = authenticator.Sign(body);
        var id = Convert.ToHexStringLower(SHA256.HashData(body));
        var prepared = await replica.ExecuteAsync(new PublicationRequest("prepare", body, signature, id), cancellationToken).ConfigureAwait(false);
        RequireReceipt(prepared, operation, id, "prepared");
        var activated = await replica.ExecuteAsync(new PublicationRequest("activate", ReadOnlyMemory<byte>.Empty, authenticator.SignActivation(id), id), cancellationToken).ConfigureAwait(false);
        RequireReceipt(activated, operation, id, "activated");
        await store.MarkActivatedAsync(operation, activated, cancellationToken).ConfigureAwait(false);
        return true;
    }

    private static void RequireReceipt(PublicationReply receipt, Domain.ZoneOperation operation, string id, string state)
    {
        if (!string.Equals(receipt.PublicationId, id, StringComparison.Ordinal) || !string.Equals(receipt.NodeId, operation.TargetNode, StringComparison.Ordinal)
            || receipt.ZoneId != operation.Snapshot.ZoneId || receipt.Revision != operation.Snapshot.Revision
            || !string.Equals(receipt.ContentHash, operation.Snapshot.ContentHash, StringComparison.Ordinal) || !string.Equals(receipt.State, state, StringComparison.Ordinal))
            throw new InvalidOperationException("Publication acknowledgement does not match the requested node and generation.");
    }
}
