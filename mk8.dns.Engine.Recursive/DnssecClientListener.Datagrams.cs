using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientListener
{
    private async Task ServeUdpAsync(Socket socket, CancellationToken token)
    {
        var bytes = new byte[DnsMessageCodec.MaximumMessageBytes];
        var any = new IPEndPoint(endpoint.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
        while (true)
        {
            token.ThrowIfCancellationRequested();
            SocketReceiveMessageFromResult received;
            try { received = await socket.ReceiveMessageFromAsync(bytes, SocketFlags.None, any, token).ConfigureAwait(false); }
            catch (SocketException error) when (VanishedPeer(error)) { continue; }
            if (received.SocketFlags.HasFlag(SocketFlags.Truncated)) continue;
            if (received.RemoteEndPoint is not IPEndPoint peer) throw new IOException("Missing native datagram peer.");
            // Process immediately before send; no previously prepared packet queue.
            // Socket acceptance/backpressure is still NOT atomic fresh peer receipt.
            var reply = await processor.ProcessAsync(bytes.AsMemory(0, received.ReceivedBytes),
                peer.Address.GetAddressBytes(), tcp: false, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            var message = reply.GetMessage();
            if (message.Length > DnsMessageCodec.MaximumUdpPayloadSize) throw new InvalidDataException("Oversized recursive UDP reply.");
            if (message.Length == 0) continue;
            try { _ = await socket.SendToAsync(message, SocketFlags.None, peer, token).ConfigureAwait(false); }
            catch (SocketException error) when (VanishedPeer(error)) { }
        }
    }

    private static bool VanishedPeer(SocketException error)
        => error.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused;
}
