using System.Text.Json;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

internal static class ControlErrors
{
    internal static void Validate(ControlFrame request, int maximum, uint version = ProtocolVersion.Current)
    {
        if (request.ProtocolVersion != version)
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "Unsupported control protocol version."));
        if (request.Payload.Length == 0 || request.Payload.Length > maximum - 32)
            throw new ArgumentException("Invalid control message bounds.", nameof(request));
    }

    internal static bool IsContractFailure(Exception exception) => exception is ArgumentException or FormatException or JsonException or UnauthorizedAccessException or InvalidOperationException or KeyNotFoundException or IOException or InvalidDataException;
    internal static RpcException Convert(Exception exception) => new(new Status(exception switch
    {
        UnauthorizedAccessException => StatusCode.PermissionDenied,
        ArgumentException or FormatException or JsonException => StatusCode.InvalidArgument,
        KeyNotFoundException => StatusCode.NotFound,
        IOException or InvalidDataException => StatusCode.Unavailable,
        _ => StatusCode.FailedPrecondition,
    }, "Control request was rejected."));
}
