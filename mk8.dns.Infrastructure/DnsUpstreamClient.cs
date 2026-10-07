using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Infrastructure;

public sealed class DnsUpstreamClient : IDnsUpstream
{
    private readonly Func<DnsServerEndpoint, bool> permits;
    private readonly TimeSpan timeout;

    public DnsUpstreamClient(Func<DnsServerEndpoint, bool> permits, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(permits);
        if (timeout < TimeSpan.FromMilliseconds(50) || timeout > TimeSpan.FromSeconds(10))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        this.permits = permits;
        this.timeout = timeout;
    }

    public async ValueTask<DnsAnswer> ExchangeAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        cancellationToken.ThrowIfCancellationRequested();
        if (!permits(server))
            throw new IOException("Resolver egress policy rejected the upstream endpoint.");
        var id = (ushort)RandomNumberGenerator.GetInt32(65536);
        var query = UpstreamMessageCodec.EncodeQuery(id, question);
        var endpoint = new IPEndPoint(new IPAddress(server.GetAddress()), server.Port);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            using var udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
                udp.DualMode = false;
            await udp.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(false);
            if (await udp.SendAsync(query, SocketFlags.None, deadline.Token).ConfigureAwait(false) != query.Length)
                throw new IOException("Incomplete upstream DNS datagram write.");
            var buffer = new byte[65535];
            while (true)
            {
                var bytes = await udp.ReceiveAsync(buffer, SocketFlags.None, deadline.Token).ConfigureAwait(false);
                UpstreamResponse reply;
                try
                {
                    reply = UpstreamMessageCodec.DecodeResponse(buffer.AsSpan(0, bytes), id, question);
                }
                catch (FormatException)
                {
                    // Discard mismatches/malformed packets within the original exchange deadline.
                    continue;
                }
                return reply.Truncated ? await ExchangeTcpAsync(endpoint, query, id, question, deadline.Token).ConfigureAwait(false) : reply.Answer;
            }
        }
        catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The upstream DNS exchange deadline elapsed.", error);
        }
        catch (SocketException error)
        {
            throw new IOException("The upstream DNS transport failed.", error);
        }
    }

    private static async ValueTask<DnsAnswer> ExchangeTcpAsync(IPEndPoint endpoint, byte[] query, ushort id, DnsQuestion question, CancellationToken cancellationToken)
    {
        using var tcp = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
            tcp.DualMode = false;
        await tcp.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
        using var stream = new NetworkStream(tcp, ownsSocket: false);
        var framed = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed, 2);
        await stream.WriteAsync(framed, cancellationToken).ConfigureAwait(false);
        var prefix = new byte[2];
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
        if (length < 12)
            throw new IOException("Invalid upstream DNS stream frame.");
        var response = new byte[length];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);
        var parsed = UpstreamMessageCodec.DecodeResponse(response, id, question);
        if (parsed.Truncated)
            throw new IOException("A DNS stream reply cannot remain truncated.");
        return parsed.Answer;
    }
}
