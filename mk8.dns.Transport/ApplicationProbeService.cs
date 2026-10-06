using Grpc.Core;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

internal sealed class ApplicationProbeService : ApplicationProbe.ApplicationProbeBase, IDisposable
{
    private readonly IApplicationStatusSource source;
    private readonly SemaphoreSlim admission = new(16, 16);

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
        if (!await admission.WaitAsync(0, context.CancellationToken).ConfigureAwait(false))
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Application probe capacity exhausted."));
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
            admission.Release();
        }
    }

    public void Dispose() => admission.Dispose();
}
