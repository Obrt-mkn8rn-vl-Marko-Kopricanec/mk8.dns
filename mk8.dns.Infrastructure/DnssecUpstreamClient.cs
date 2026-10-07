using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Infrastructure;

public sealed class DnssecUpstreamClient : IDnssecUpstream
{
    private readonly Func<DnsServerEndpoint, bool> permits;
    private readonly TimeSpan timeout;
    private readonly TimeProvider time;

    public DnssecUpstreamClient(Func<DnsServerEndpoint, bool> permits, TimeSpan timeout, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(permits);
        if (timeout < TimeSpan.FromMilliseconds(50) || timeout > TimeSpan.FromSeconds(10))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        this.permits = permits;
        this.timeout = timeout;
        this.time = time ?? TimeProvider.System;
    }

    public async ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(server);
        cancellationToken.ThrowIfCancellationRequested();
        if (!permits(server))
            throw new IOException("Resolver egress policy rejected the DNSSEC upstream endpoint.");
        var id = (ushort)RandomNumberGenerator.GetInt32(65536);
        var query = UpstreamMessageCodec.EncodeDnssecQuery(id, question);
        var endpoint = new IPEndPoint(new IPAddress(server.GetAddress()), server.Port);
        using var expiration = new CancellationTokenSource(timeout, time);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, expiration.Token);
        try
        {
            using var udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
                udp.DualMode = false;
            await udp.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(false);
            if (await udp.SendAsync(query, SocketFlags.None, deadline.Token).ConfigureAwait(false) != query.Length)
                throw new IOException("Incomplete DNSSEC upstream datagram write.");
            var buffer = new byte[65535];
            while (true)
            {
                var length = await udp.ReceiveAsync(buffer, SocketFlags.None, deadline.Token).ConfigureAwait(false);
                if (length > 1232)
                    continue; // Respect this exchange's advertised datagram payload bound.
                DnssecUpstreamResponse response;
                try { response = UpstreamMessageCodec.DecodeDnssecResponse(buffer.AsSpan(0, length), id, question, server); }
                catch (FormatException) { continue; }
                if (!response.Truncated)
                    return response.Evidence;
                if (!permits(server))
                    throw new IOException("Resolver egress policy rejected the DNSSEC TCP retry.");
                return await ExchangeTcpAsync(endpoint, query, id, question, server, deadline.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The DNSSEC upstream exchange deadline elapsed.", error);
        }
        catch (SocketException error)
        {
            throw new IOException("The DNSSEC upstream transport failed.", error);
        }
    }

    private static async ValueTask<DnsUpstreamEvidence> ExchangeTcpAsync(IPEndPoint endpoint, byte[] query, ushort id,
        DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
    {
        using var tcp = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
            tcp.DualMode = false;
        await tcp.ConnectAsync(endpoint, cancellationToken).ConfigureAwait(false);
        using var stream = new NetworkStream(tcp, ownsSocket: false);
        var frame = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)query.Length);
        query.CopyTo(frame, 2);
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        var prefix = new byte[2];
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
        if (length < 12)
            throw new IOException("Invalid DNSSEC upstream stream frame.");
        var bytes = new byte[length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        var response = UpstreamMessageCodec.DecodeDnssecResponse(bytes, id, question, server);
        if (response.Truncated)
            throw new IOException("A DNSSEC stream reply cannot remain truncated.");
        return response.Evidence;
    }
}
