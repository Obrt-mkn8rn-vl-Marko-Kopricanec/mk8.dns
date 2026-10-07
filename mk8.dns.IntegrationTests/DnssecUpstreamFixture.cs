using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;

namespace Mk8.Dns.IntegrationTests;

internal static class DnssecUpstreamFixture
{
    internal static DnsQuestion Question { get; } = new(DnsName.Parse("www.example."), 1, 1);
    internal static UdpClient Bind(bool ipv6)
    {
        var socket = new UdpClient(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        if (ipv6) socket.Client.DualMode = false;
        socket.Client.Bind(new IPEndPoint(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0));
        return socket;
    }
    internal static DnsServerEndpoint Endpoint(UdpClient socket)
    {
        var bound = (IPEndPoint)socket.Client.LocalEndPoint!;
        return new DnsServerEndpoint(bound.Address.GetAddressBytes(), (ushort)bound.Port);
    }
    internal static byte[] Reply(byte[] request, ushort flags = 0x84b0, byte[]? data = null, byte extendedCode = 0)
    {
        var end = 12;
        while (request[end] != 0) end += request[end] + 1;
        end += 5; data ??= [192, 0, 2, 42];
        var result = new byte[end + 12 + data.Length + 11]; request.AsSpan(0, end).CopyTo(result);
        Write16(result, 2, flags); Write16(result, 6, 1); Write16(result, 8, 0); Write16(result, 10, 1);
        result[end] = 0xc0; result[end + 1] = 0x0c; Write16(result, end + 2, data.Length == 4 ? (ushort)1 : (ushort)65280); Write16(result, end + 4, 1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(end + 6), 300); Write16(result, end + 10, (ushort)data.Length); data.CopyTo(result, end + 12);
        var opt = end + 12 + data.Length; Write16(result, opt + 1, 41); Write16(result, opt + 3, 4096); result[opt + 5] = extendedCode; Write16(result, opt + 7, 0x8000);
        return result;
    }
    internal static void Write16(byte[] bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), value);
    internal static async Task<byte[]> ReadFrameAsync(NetworkStream stream, CancellationToken token)
    {
        var prefix = new byte[2]; await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(false);
        var frame = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)]; await stream.ReadExactlyAsync(frame, token).ConfigureAwait(false); return frame;
    }
    internal static async Task SendFrameAsync(NetworkStream stream, byte[] response, CancellationToken token)
    {
        var prefix = new byte[2]; Write16(prefix, 0, (ushort)response.Length);
        await stream.WriteAsync(prefix.AsMemory(0, 1), token).ConfigureAwait(false); await stream.WriteAsync(prefix.AsMemory(1), token).ConfigureAwait(false);
        await stream.WriteAsync(response.AsMemory(0, 13), token).ConfigureAwait(false); await stream.WriteAsync(response.AsMemory(13), token).ConfigureAwait(false);
    }

}
