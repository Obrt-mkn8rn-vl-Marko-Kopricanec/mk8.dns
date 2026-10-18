using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

// An owned Unix protocol peer, not a database or a configured deployment target.
internal static class PostgresSnapshotPeer
{
    internal static async Task ChallengeAsync(Socket listener, string? password, CancellationToken cancellationToken)
    {
        using var socket = await listener.AcceptAsync(cancellationToken).ConfigureAwait(true);
        var stream = new NetworkStream(socket, ownsSocket: false);
        await using var lifetime = stream.ConfigureAwait(true);
        var startup = await ReadPayloadAsync(stream, cancellationToken).ConfigureAwait(true);
        Assert.Equal(196608, BinaryPrimitives.ReadInt32BigEndian(startup));
        var fields = Encoding.UTF8.GetString(startup, 4, startup.Length - 4).Split('\0');
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < fields.Length - 2; index += 2) values.Add(fields[index], fields[index + 1]);
        Assert.Equal("fixture", values["user"]);
        Assert.Equal("fixture", values["database"]);
        Assert.Equal("UTF8", values["client_encoding"]);
        Assert.Equal("UTC", values["TimeZone"]);
        Assert.Equal("mk8.dns", values["application_name"]);
        Assert.Equal(" ", values["options"]);
        await stream.WriteAsync(new byte[] { (byte)'R', 0, 0, 0, 8, 0, 0, 0, 3 }, cancellationToken).ConfigureAwait(true);
        var type = new byte[1];
        var received = await stream.ReadAsync(type, cancellationToken).ConfigureAwait(true);
        if (password is null)
        {
            Assert.Equal(0, received);
            return;
        }
        Assert.Equal(1, received);
        Assert.Equal((byte)'p', type[0]);
        var credential = await ReadPayloadAsync(stream, cancellationToken).ConfigureAwait(true);
        Assert.Equal(password + '\0', Encoding.UTF8.GetString(credential));
        await RefuseAsync(stream, cancellationToken).ConfigureAwait(true);
    }

    private static async Task<byte[]> ReadPayloadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(true);
        var length = BinaryPrimitives.ReadInt32BigEndian(prefix);
        Assert.InRange(length, 4, 4096);
        var payload = new byte[length - 4];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(true);
        return payload;
    }

    private static async Task RefuseAsync(Stream stream, CancellationToken cancellationToken)
    {
        var payload = Encoding.UTF8.GetBytes("SFATAL\0VFATAL\0C28000\0MControlledFixtureRefusal\0\0");
        var frame = new byte[payload.Length + 5];
        frame[0] = (byte)'E';
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(1), payload.Length + 4);
        payload.CopyTo(frame, 5);
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(true);
    }
}
