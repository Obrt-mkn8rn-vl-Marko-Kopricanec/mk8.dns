using System.Buffers.Binary;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

internal static class TcpSessionFixture
{
    internal static byte[] Frame(byte[] message)
    {
        var frame = new byte[message.Length + 2]; BinaryPrimitives.WriteUInt16BigEndian(frame, checked((ushort)message.Length));
        message.CopyTo(frame, 2); return frame;
    }

    internal static byte[][] Replies(TcpSessionStream stream)
    {
        var bytes = stream.Output; var offset = 0; List<byte[]> messages = [];
        while (offset < bytes.Length)
        {
            Assert.InRange(bytes.Length - offset, 2, 65537 * 256);
            var length = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset)); offset += 2;
            Assert.InRange(length, 12, bytes.Length - offset);
            messages.Add(bytes.AsSpan(offset, length).ToArray()); offset += length;
        }
        return [.. messages];
    }

    internal static async Task SettleAsync(DnssecClientTcpSession session, Type? expected = null)
    {
        var actual = session.DisposeAsync().AsTask();
        await TestTaskSettlement.WaitAsync(actual.WaitAsync(CancellationToken.None), AnchorRefreshFixture.Timeout,
            error => expected?.IsInstanceOfType(error) == true).ConfigureAwait(true);
    }
}
