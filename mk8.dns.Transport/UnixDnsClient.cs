using System.Net.Sockets;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

public sealed class UnixDnsClient : IDnsExchange, IDisposable
{
    private readonly GrpcChannel channel;
    private readonly AuthoritativeQuery.AuthoritativeQueryClient client;

    public UnixDnsClient(string socketPath)
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
            MaxReceiveMessageSize = QueryHostingExtensions.MaximumExchangeBytes,
            MaxSendMessageSize = QueryHostingExtensions.MaximumExchangeBytes,
        });
        client = new AuthoritativeQuery.AuthoritativeQueryClient(channel);
    }

    public async ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken)
    {
        if (message.Length > ushort.MaxValue || peerAddress.Length is not (4 or 16))
            throw new ArgumentException("Invalid DNS exchange bounds.", nameof(message));
        using var call = client.ExchangeAsync(new DnsRequest
        {
            ProtocolVersion = ProtocolVersion.Current,
            Message = ByteString.CopyFrom(message.Span),
            Tcp = tcp,
            PeerAddress = ByteString.CopyFrom(peerAddress.Span),
        }, deadline: DateTime.UtcNow.AddSeconds(2), cancellationToken: cancellationToken);
        var reply = await call.ResponseAsync.ConfigureAwait(false);
        if (reply.ProtocolVersion != ProtocolVersion.Current || reply.Message.Length > ushort.MaxValue)
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "Invalid DNS reply contract."));
        return reply.Message.ToByteArray();
    }

    public void Dispose() => channel.Dispose();
}
