using System.Text.Json;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

internal sealed class PublicationService(IZonePublication source) : ZonePublication.ZonePublicationBase
{
    private int active;

    public override async Task<ControlFrame> Execute(ControlFrame request, ServerCallContext context)
    {
        context.CancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Increment(ref active) > 4)
        {
            _ = Interlocked.Decrement(ref active);
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Publication admission is full."));
        }
        try
        {
            ControlErrors.Validate(request, ControlHostingExtensions.MaximumPublicationBytes);
            var command = JsonSerializer.Deserialize(request.Payload.Span, ControlJsonContext.Default.PublicationRequest) ?? throw new JsonException();
            if (command.PublicationId is null)
                throw new JsonException();
            var reply = await source.ExecuteAsync(command, context.CancellationToken).ConfigureAwait(false);
            return new ControlFrame { ProtocolVersion = ProtocolVersion.Current, Payload = ByteString.CopyFrom(JsonSerializer.SerializeToUtf8Bytes(reply, ControlJsonContext.Default.PublicationReply)) };
        }
        catch (Exception exception) when (ControlErrors.IsContractFailure(exception))
        {
            throw ControlErrors.Convert(exception);
        }
        finally
        {
            _ = Interlocked.Decrement(ref active);
        }
    }
}
