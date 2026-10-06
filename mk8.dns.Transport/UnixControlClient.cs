using System.Net.Sockets;
using System.Text.Json;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

public sealed class UnixControlClient : IZoneManagement, IZonePublication, IDisposable
{
    private readonly GrpcChannel channel;
    private readonly ZoneManagement.ZoneManagementClient management;
    private readonly ZonePublication.ZonePublicationClient publication;

    public UnixControlClient(string socketPath)
    {
        PrivateUnixSocket.ValidatePath(socketPath);
        var endpoint = new UnixDomainSocketEndPoint(socketPath);
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
            ConnectTimeout = TimeSpan.FromSeconds(2),
            UseProxy = false,
            MaxConnectionsPerServer = 1,
        };
        channel = GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions
        {
            HttpHandler = handler,
            DisposeHttpClient = true,
            MaxReceiveMessageSize = ControlHostingExtensions.MaximumManagementBytes,
            MaxSendMessageSize = ControlHostingExtensions.MaximumManagementBytes,
        });
        management = new ZoneManagement.ZoneManagementClient(channel);
        publication = new ZonePublication.ZonePublicationClient(channel);
    }

    public async ValueTask<ManagementReply> ExecuteAsync(ManagementRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var frame = Frame(JsonSerializer.SerializeToUtf8Bytes(request, ControlJsonContext.Default.ManagementRequest), ControlHostingExtensions.MaximumManagementBytes, ProtocolVersion.Management);
        using var call = management.ExecuteAsync(frame, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: cancellationToken);
        var reply = await call.ResponseAsync.ConfigureAwait(false);
        ControlErrors.Validate(reply, ControlHostingExtensions.MaximumManagementBytes, ProtocolVersion.Management);
        return JsonSerializer.Deserialize(reply.Payload.Span, ControlJsonContext.Default.ManagementReply) ?? throw new RpcException(new Status(StatusCode.Internal, "Empty management reply."));
    }

    public async ValueTask<PublicationReply> ExecuteAsync(PublicationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var frame = Frame(JsonSerializer.SerializeToUtf8Bytes(request, ControlJsonContext.Default.PublicationRequest), ControlHostingExtensions.MaximumPublicationBytes);
        using var call = publication.ExecuteAsync(frame, deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: cancellationToken);
        var reply = await call.ResponseAsync.ConfigureAwait(false);
        ControlErrors.Validate(reply, ProtocolVersion.MaximumMessageBytes);
        return JsonSerializer.Deserialize(reply.Payload.Span, ControlJsonContext.Default.PublicationReply) ?? throw new RpcException(new Status(StatusCode.Internal, "Empty publication reply."));
    }

    public void Dispose() => channel.Dispose();

    private static ControlFrame Frame(byte[] payload, int maximum, uint version = ProtocolVersion.Current)
    {
        if (payload.Length > maximum - 32)
            throw new ArgumentException("Control request exceeds its message bound.", nameof(payload));
        return new ControlFrame { ProtocolVersion = version, Payload = ByteString.CopyFrom(payload) };
    }
}
