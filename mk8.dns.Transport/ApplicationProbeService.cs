using Grpc.Core;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

internal sealed class ApplicationProbeService : ApplicationProbe.ApplicationProbeBase
{
    private readonly IApplicationStatusSource source;
    private int active;

    public ApplicationProbeService(IApplicationStatusSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        this.source = source;
    }

    public override async Task<StatusReply> GetStatus(StatusRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        if (request.ProtocolVersion != ProtocolVersion.Current)
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "Unsupported Application protocol version."));
        context.CancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Increment(ref active) > 16)
        {
            _ = Interlocked.Decrement(ref active);
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Application probe capacity exhausted."));
        }
        try
        {
            var status = await source.GetStatusAsync(context.CancellationToken).ConfigureAwait(false);
            return new StatusReply
            {
                ProtocolVersion = status.ProtocolVersion,
                NodeId = status.NodeId,
                Role = status.Role,
                DnsReady = status.DnsReady,
                ActiveSnapshots = status.ActiveSnapshots,
            };
        }
        catch (IOException)
        {
            throw new RpcException(new Status(StatusCode.Unavailable, "Application state is unavailable."));
        }
        finally
        {
            _ = Interlocked.Decrement(ref active);
        }
    }
}
