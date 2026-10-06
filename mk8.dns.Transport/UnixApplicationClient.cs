using System.Net.Sockets;
using Grpc.Core;
using Grpc.Net.Client;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

public sealed class UnixApplicationClient : IDisposable
{
    private readonly GrpcChannel channel;
    private readonly ApplicationProbe.ApplicationProbeClient client;

    public UnixApplicationClient(string socketPath)
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
            MaxReceiveMessageSize = ProtocolVersion.MaximumMessageBytes,
            MaxSendMessageSize = ProtocolVersion.MaximumMessageBytes,
        });
        client = new ApplicationProbe.ApplicationProbeClient(channel);
    }

    public async Task<ApplicationStatus> GetStatusAsync(uint version, CancellationToken cancellationToken)
    {
        using var call = client.GetStatusAsync(new StatusRequest { ProtocolVersion = version }, deadline: DateTime.UtcNow.AddSeconds(2), cancellationToken: cancellationToken);
        var result = await call.ResponseAsync.ConfigureAwait(false);
        if (result.ProtocolVersion != ProtocolVersion.Current)
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "Unsupported Application protocol version."));
        return new ApplicationStatus(result.ProtocolVersion, result.NodeId, result.Role, result.DnsReady, result.ActiveSnapshots);
    }

    public void Dispose() => channel.Dispose();
}
