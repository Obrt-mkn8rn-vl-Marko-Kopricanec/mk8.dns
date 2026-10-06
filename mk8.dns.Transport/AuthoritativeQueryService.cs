using Google.Protobuf;
using Grpc.Core;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

internal sealed class AuthoritativeQueryService(IDnsExchange source) : AuthoritativeQuery.AuthoritativeQueryBase, IDisposable
{
    private readonly SemaphoreSlim admission = new(16, 16);

    public override async Task<DnsReply> Exchange(DnsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        if (request.ProtocolVersion != ProtocolVersion.Current)
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "Unsupported Application protocol version."));
        if (request.Message.Length is 0 or > ushort.MaxValue || request.PeerAddress.Length is not (4 or 16))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid DNS exchange bounds."));
        if (!await admission.WaitAsync(0, context.CancellationToken).ConfigureAwait(false))
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Query capacity exhausted."));
        try
        {
            var response = await source.ExchangeAsync(request.Message.Memory, request.Tcp, request.PeerAddress.Memory, context.CancellationToken).ConfigureAwait(false);
            if (response.Length > ushort.MaxValue)
                throw new RpcException(new Status(StatusCode.Internal, "Invalid DNS response bounds."));
            return new DnsReply { ProtocolVersion = ProtocolVersion.Current, Message = ByteString.CopyFrom(response) };
        }
        finally
        {
            admission.Release();
        }
    }

    public void Dispose() => admission.Dispose();
}
