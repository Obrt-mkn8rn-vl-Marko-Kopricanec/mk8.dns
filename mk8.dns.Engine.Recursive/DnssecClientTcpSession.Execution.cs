using System.Buffers.Binary;
using Mk8.Dns.Wire;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecClientTcpSession
{
    private async Task<DnssecClientTcpSessionResult> ExecuteAsync(CancellationToken token)
    {
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        token.ThrowIfCancellationRequested();
        if (!processor.AdmitsTcpPeer(peer)) return new(DnssecClientTcpSessionOutcome.Denied, 0, 0);
        var read = 0; var written = 0;
        for (var index = 0; index < maximumMessages; index++)
        {
            token.ThrowIfCancellationRequested();
            if (!TryBeginFrame()) return new(DnssecClientTcpSessionOutcome.Stopped, read, written);
            var prefix = new byte[2];
            // EOF is clean only BETWEEN frames. Partial prefix/payload throws.
            var first = await stream.ReadAsync(prefix.AsMemory(0, 1), token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (first == 0)
                return new(DnssecClientTcpSessionOutcome.EndOfStream, read, written);
            await stream.ReadExactlyAsync(prefix.AsMemory(1, 1), token).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
            if (length < 12) throw new InvalidDataException("A DNS TCP frame must contain a complete header.");
            var request = new byte[length];
            await stream.ReadExactlyAsync(request, token).ConfigureAwait(false);
            read++;
            var reply = await processor.ProcessAsync(request, peer, tcp: true, token).ConfigureAwait(false);
            var message = reply.GetMessage();
            if (message.Length == 0) return new(DnssecClientTcpSessionOutcome.Dropped, read, written);
            if (message.Length is < 12 or > DnsMessageCodec.MaximumMessageBytes || !DnssecClientTcpMessageCodec.IsComplete(message))
                throw new InvalidDataException("The processor did not supply a complete DNS TCP reply.");
            var frame = new byte[message.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)message.Length); message.CopyTo(frame, 2);
            // The borrowed stream may stall, buffer or accept bytes after an
            // external ACK/expiry. This is NOT atomic authenticated delivery.
            await stream.WriteAsync(frame, token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            written++;
        }
        return new(DnssecClientTcpSessionOutcome.MessageLimit, read, written);
    }
}
