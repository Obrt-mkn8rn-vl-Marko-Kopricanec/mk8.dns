using System.Text.Json;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

internal sealed class ManagementService(IZoneManagement source) : ZoneManagement.ZoneManagementBase
{
    private int active;

    public override async Task<ControlFrame> Execute(ControlFrame request, ServerCallContext context)
    {
        context.CancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Increment(ref active) > 4)
        {
            _ = Interlocked.Decrement(ref active);
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Management admission is full."));
        }
        try
        {
            ControlErrors.Validate(request, ControlHostingExtensions.MaximumManagementBytes, ProtocolVersion.Management);
            var command = JsonSerializer.Deserialize(request.Payload.Span, ControlJsonContext.Default.ManagementRequest) ?? throw new JsonException();
            var reply = await source.ExecuteAsync(command, context.CancellationToken).ConfigureAwait(false);
            var response = new ControlFrame { ProtocolVersion = ProtocolVersion.Management, Payload = ByteString.CopyFrom(JsonSerializer.SerializeToUtf8Bytes(reply, ControlJsonContext.Default.ManagementReply)) };
            ControlErrors.Validate(response, ControlHostingExtensions.MaximumManagementBytes, ProtocolVersion.Management);
            return response;
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
