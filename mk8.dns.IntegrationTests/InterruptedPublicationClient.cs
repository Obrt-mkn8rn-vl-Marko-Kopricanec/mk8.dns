using Mk8.Dns.Contracts;

namespace Mk8.Dns.IntegrationTests;

internal sealed class InterruptedPublicationClient(IZonePublication replica, bool corruptReceipt) : IZonePublication
{
    private bool interrupt = true;

    public async ValueTask<PublicationReply> ExecuteAsync(PublicationRequest request, CancellationToken cancellationToken)
    {
        var reply = await replica.ExecuteAsync(request, cancellationToken).ConfigureAwait(true);
        if (interrupt && string.Equals(request.Action, "activate", StringComparison.Ordinal))
        {
            interrupt = false;
            if (corruptReceipt)
                return reply with { NodeId = "other-replica" };
            throw new IOException("The activation completed, but its response was lost.");
        }
        return reply;
    }
}
