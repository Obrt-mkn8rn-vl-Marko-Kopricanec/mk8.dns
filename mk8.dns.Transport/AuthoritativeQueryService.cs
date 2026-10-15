using Google.Protobuf;
using Grpc.Core;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

internal sealed class AuthoritativeQueryService(IDnsExchange source) : AuthoritativeQuery.AuthoritativeQueryBase
{
    private int active;

    public override async Task<DnsReply> Exchange(DnsRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        if (request.ProtocolVersion != ProtocolVersion.Current)
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "Unsupported Application protocol version."));
        if (request.Message.Length is 0 or > ushort.MaxValue || request.PeerAddress.Length is not (4 or 16))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid DNS exchange bounds."));
        context.CancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Increment(ref active) > 16)
        {
            _ = Interlocked.Decrement(ref active);
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Query capacity exhausted."));
        }
        try
        {
            var response = await source.ExchangeAsync(request.Message.Memory, request.Tcp, request.PeerAddress.Memory, context.CancellationToken).ConfigureAwait(false);
            if (response.Length > ushort.MaxValue)
                throw new RpcException(new Status(StatusCode.Internal, "Invalid DNS response bounds."));
            return new DnsReply { ProtocolVersion = ProtocolVersion.Current, Message = ByteString.CopyFrom(response) };
        }
        finally
        {
            _ = Interlocked.Decrement(ref active);
        }
    }
}
