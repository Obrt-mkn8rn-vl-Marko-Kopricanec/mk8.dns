using System.Text.Json;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

internal sealed class ManagementService(IZoneManagement source) : ZoneManagement.ZoneManagementBase, IDisposable
{
    private readonly SemaphoreSlim admission = new(4, 4);

    public override async Task<ControlFrame> Execute(ControlFrame request, ServerCallContext context)
    {
        if (!await admission.WaitAsync(0, context.CancellationToken).ConfigureAwait(false))
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Management admission is full."));
        try
        {
            ControlErrors.Validate(request, ControlHostingExtensions.MaximumManagementBytes);
            var command = JsonSerializer.Deserialize(request.Payload.Span, ControlJsonContext.Default.ManagementRequest) ?? throw new JsonException();
            var reply = await source.ExecuteAsync(command, context.CancellationToken).ConfigureAwait(false);
            return new ControlFrame { ProtocolVersion = ProtocolVersion.Current, Payload = ByteString.CopyFrom(JsonSerializer.SerializeToUtf8Bytes(reply, ControlJsonContext.Default.ManagementReply)) };
        }
        catch (Exception exception) when (ControlErrors.IsContractFailure(exception))
        {
            throw ControlErrors.Convert(exception);
        }
        finally
        {
            admission.Release();
        }
    }

    public void Dispose() => admission.Dispose();
}
