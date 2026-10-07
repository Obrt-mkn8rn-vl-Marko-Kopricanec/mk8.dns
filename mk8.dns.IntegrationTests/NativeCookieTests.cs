using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class NativeCookieTests
{
    [Theory]
    [InlineData("127.0.0.2")]
    [InlineData("::1")]
    public async Task OriginalPeerCookieBootstrapLargeAnswersAndPersistentTcpCrossThePrivateBoundary(string address)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8dns-cookie-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            await RunAsync(root, IPAddress.Parse(address)).ConfigureAwait(true);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RunAsync(string root, IPAddress address)
    {
        var zone = Guid.NewGuid();
        var state = Path.Combine(root, "state");
        await SeedAsync(state, zone).ConfigureAwait(true);
        var path = Path.Combine(root, "run", "app.sock");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var token = timeout.Token;
        var application = new HostProcess("mk8.dns.Application", ["--socket", path, "--state", state, "--node", "cookies", "--role", "authoritative-replica", "--zones", zone.ToString("N")], Port(IPAddress.Loopback));
        await using (application.ConfigureAwait(true))
        {
            var dns = Port(address);
            var health = Port(IPAddress.Loopback);
            var gateway = new HostProcess("mk8.dns.Gateway", ["--socket", path, "--health-port", health.ToString(CultureInfo.InvariantCulture), "--dns-address", address.ToString(), "--dns-port", dns.ToString(CultureInfo.InvariantCulture)], Port(IPAddress.Loopback));
            await using (gateway.ConfigureAwait(true))
            {
                await HealthyAsync(health, application, gateway, token).ConfigureAwait(true);
                await ExerciseAsync(new IPEndPoint(address, dns), token).ConfigureAwait(true);
                await gateway.StopAsync(token).ConfigureAwait(true);
                await application.StopAsync(token).ConfigureAwait(true);
                Assert.Equal(0, gateway.ExitCode);
                Assert.Equal(0, application.ExitCode);
            }
        }
    }

    private static async Task ExerciseAsync(IPEndPoint endpoint, CancellationToken token)
    {
        using var udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        var request = Query();
        var limited = await UdpAsync(udp, endpoint, request, token).ConfigureAwait(true);
        Assert.Equal((byte)0x87, limited[2]);
        Assert.True(limited.Length <= 512);
        var hello = await UdpAsync(udp, endpoint, Query(new byte[8]), token).ConfigureAwait(true);
        Assert.Equal((byte)7, (byte)(hello[3] & 15));
        Assert.Equal((byte)1, hello[^34]);
        Assert.Equal(new byte[] { 0, 10, 0, 24 }, hello[^28..^24]);
        var proof = hello[^24..];
        var full = await UdpAsync(udp, endpoint, Query(proof), token).ConfigureAwait(true);
        Assert.Equal((byte)0x85, full[2]);
        Assert.Equal((ushort)5, BinaryPrimitives.ReadUInt16BigEndian(full.AsSpan(6)));
        Assert.InRange(full.Length, 513, 1232);
        proof[^1] ^= 1;
        var bad = await UdpAsync(udp, endpoint, Query(proof), token).ConfigureAwait(true);
        Assert.Equal((byte)7, (byte)(bad[3] & 15));
        using var tcp = new TcpClient(endpoint.AddressFamily);
        await tcp.ConnectAsync(endpoint.Address, endpoint.Port, token).ConfigureAwait(true);
        using var stream = tcp.GetStream();
        var tcpRequest = Query(type: 65284);
        var frame = new byte[tcpRequest.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)tcpRequest.Length);
        tcpRequest.CopyTo(frame, 2);
        await stream.WriteAsync(frame.Concat(frame).ToArray(), token).ConfigureAwait(true);
        for (var count = 0; count < 2; count++)
        {
            var prefix = new byte[2];
            await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(true);
            var reply = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
            await stream.ReadExactlyAsync(reply, token).ConfigureAwait(true);
            Assert.True(reply.Length > 1232);
            Assert.Equal((ushort)6, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(6)));
            Assert.Equal((byte)0x85, reply[2]);
        }
    }

    private static async Task<byte[]> UdpAsync(Socket socket, IPEndPoint endpoint, byte[] query, CancellationToken token)
    {
        _ = await socket.SendToAsync(query, SocketFlags.None, endpoint, token).ConfigureAwait(true);
        var bytes = new byte[1232];
        var received = await socket.ReceiveFromAsync(bytes, SocketFlags.None, endpoint, token).ConfigureAwait(true);
        Assert.Equal(endpoint, received.RemoteEndPoint);
        return bytes[..received.ReceivedBytes];
    }

    private static byte[] Query(byte[]? cookie = null, ushort type = 65283)
    {
        var owner = DnsName.Parse("large.example.").ToWire();
        var query = new byte[12 + owner.Length + 4 + 11 + (cookie is null ? 0 : cookie.Length + 4)];
        BinaryPrimitives.WriteUInt16BigEndian(query, 0xbeef);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(2), 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(10), 1);
        owner.CopyTo(query, 12);
        var offset = 12 + owner.Length;
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset), type);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 2), 1);
        offset += 4;
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 1), 41);
        BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 3), 1232);
        if (cookie is not null)
        {
            BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 9), (ushort)(cookie.Length + 4));
            BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 11), 10);
            BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(offset + 13), (ushort)cookie.Length);
            cookie.CopyTo(query, offset + 15);
        }
        return query;
    }

    private static async Task SeedAsync(string state, Guid id)
    {
        var origin = DnsName.Parse("example.");
        var soa = DnsName.Parse("ns.example.").ToWire().Concat(DnsName.Parse("hostmaster.example.").ToWire()).Concat(new byte[20]).ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(soa.Length - 20), 1);
        var records = new List<DnsRecord> { new(origin, 6, 300, soa), new(origin, 2, 300, DnsName.Parse("ns.example.").ToWire()) };
        records.AddRange(Enumerable.Range(1, 5).Select(index => new DnsRecord(DnsName.Parse("large.example."), 65283, 300, Enumerable.Repeat((byte)index, 220).ToArray())));
        records.AddRange(Enumerable.Range(1, 6).Select(index => new DnsRecord(DnsName.Parse("large.example."), 65284, 300, Enumerable.Repeat((byte)index, 240).ToArray())));
        var store = new FileZoneSnapshotStore(state);
        await using (store.ConfigureAwait(true))
            await store.ActivateAsync(ZoneBundleCodec.Compile(id, 1, new AuthoritativeZone(origin, records)), CancellationToken.None).ConfigureAwait(true);
    }

    private static int Port(IPAddress address)
    {
        using var listener = new TcpListener(address, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task HealthyAsync(int health, HostProcess application, HostProcess gateway, CancellationToken token)
    {
        using var handler = new SocketsHttpHandler { UseProxy = false };
        using var http = new HttpClient(handler);
        var endpoint = new Uri(FormattableString.Invariant($"http://127.0.0.1:{health}/health/ready"));
        while (true)
        {
            Assert.False(application.HasExited);
            Assert.False(gateway.HasExited);
            try
            {
                using var response = await http.GetAsync(endpoint, token).ConfigureAwait(true);
                if (response.IsSuccessStatusCode)
                    return;
            }
            catch (HttpRequestException) { }
            await Task.Delay(30, token).ConfigureAwait(true);
        }
    }
}
