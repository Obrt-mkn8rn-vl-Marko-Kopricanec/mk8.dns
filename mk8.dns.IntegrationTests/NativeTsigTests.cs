using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class NativeTsigTests
{
    private static readonly byte[] Secret = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
    private static readonly byte[] KeyName = DnsName.Parse("query-key.").ToWire();
    private static readonly byte[] Algorithm = DnsName.Parse("hmac-sha256.").ToWire();

    [Theory]
    [InlineData("127.0.0.2")]
    [InlineData("::1")]
    public async Task NativeSignedUdpAndPipelinedTcpCrossUnchangedPrivateQueryTransport(string address)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8dns-tsig-" + Guid.NewGuid().ToString("N"));
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
        var file = Path.Combine(root, "tsig.keys");
        WriteKeys(file);
        var path = Path.Combine(root, "run", "app.sock");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var token = timeout.Token;
        var application = new HostProcess("mk8.dns.Application", ["--tsig-key-file", file, "--socket", path, "--state", state, "--node", "tsig", "--role", "authoritative-replica", "--zones", zone.ToString("N")], Port(IPAddress.Loopback));
        await using (application.ConfigureAwait(true))
        {
            var dns = Port(address); var health = Port(IPAddress.Loopback);
            var gateway = new HostProcess("mk8.dns.Gateway", ["--socket", path, "--health-port", health.ToString(CultureInfo.InvariantCulture), "--dns-address", address.ToString(), "--dns-port", dns.ToString(CultureInfo.InvariantCulture)], Port(IPAddress.Loopback));
            await using (gateway.ConfigureAwait(true))
            {
                await HealthyAsync(health, application, gateway, token).ConfigureAwait(true);
                await ExerciseAsync(new IPEndPoint(address, dns), token).ConfigureAwait(true);
                await gateway.StopAsync(token).ConfigureAwait(true); await application.StopAsync(token).ConfigureAwait(true);
                Assert.Equal(0, gateway.ExitCode); Assert.Equal(0, application.ExitCode);
            }
        }
    }

    private static async Task ExerciseAsync(IPEndPoint endpoint, CancellationToken token)
    {
        var query = Query();
        using var udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        _ = await udp.SendToAsync(query, SocketFlags.None, endpoint, token).ConfigureAwait(true);
        var bytes = new byte[1232];
        var received = await udp.ReceiveFromAsync(bytes, SocketFlags.None, endpoint, token).ConfigureAwait(true);
        Assert.Equal(endpoint, received.RemoteEndPoint); Verify(bytes[..received.ReceivedBytes], query);
        using var tcp = new TcpClient(endpoint.AddressFamily);
        await tcp.ConnectAsync(endpoint.Address, endpoint.Port, token).ConfigureAwait(true);
        using var stream = tcp.GetStream();
        var frame = new byte[query.Length + 2]; BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)query.Length); query.CopyTo(frame, 2);
        await stream.WriteAsync(frame.Concat(frame).ToArray(), token).ConfigureAwait(true);
        for (var count = 0; count < 2; count++)
        {
            var prefix = new byte[2]; await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(true);
            var reply = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)]; await stream.ReadExactlyAsync(reply, token).ConfigureAwait(true); Verify(reply, query);
        }
    }

    private static byte[] Query()
    {
        var question = DnsName.Parse("www.example.").ToWire().Concat(new byte[] { 0, 1, 0, 1 }).ToArray();
        var plain = new byte[] { 0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 }.Concat(question).ToArray();
        var timers = Timers();
        var variables = KeyName.Concat(new byte[] { 0, 255, 0, 0, 0, 0 }).Concat(Algorithm).Concat(timers).Concat(new byte[4]).ToArray();
        var mac = HMACSHA256.HashData(Secret, plain.Concat(variables).ToArray());
        var data = Algorithm.Concat(timers).Concat(new byte[] { 0, 32 }).Concat(mac).Concat(new byte[] { 0xbe, 0xef, 0, 0, 0, 0 }).ToArray();
        var record = KeyName.Concat(new byte[] { 0, 250, 0, 255, 0, 0, 0, 0, 0, (byte)data.Length }).Concat(data).ToArray();
        plain[11] = 1;
        return plain.Concat(record).ToArray();
    }

    private static void Verify(byte[] response, byte[] query)
    {
        var questionLength = 17; var unsignedLength = 12 + questionLength + 16;
        Assert.Equal(new byte[] { 0xbe, 0xef, 0x85, 0, 0, 1, 0, 1, 0, 0, 0, 1 }, response[..12]);
        Assert.Equal(query.AsSpan(12, questionLength).ToArray(), response.AsSpan(12, questionLength).ToArray());
        Assert.Equal(new byte[] { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 42 }, response.AsSpan(29, 16).ToArray());
        Assert.Equal(127, response.Length); Assert.Equal(KeyName, response.AsSpan(unsignedLength, KeyName.Length).ToArray());
        var data = unsignedLength + KeyName.Length + 10;
        Assert.Equal(Algorithm, response.AsSpan(data, Algorithm.Length).ToArray());
        var timers = response.AsSpan(data + Algorithm.Length, 8).ToArray();
        var signed = ((long)BinaryPrimitives.ReadUInt16BigEndian(timers) << 32) | BinaryPrimitives.ReadUInt32BigEndian(timers.AsSpan(2));
        Assert.InRange(Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - signed), 0, 5); Assert.Equal((ushort)300, BinaryPrimitives.ReadUInt16BigEndian(timers.AsSpan(6)));
        var unsigned = response[..unsignedLength]; unsigned[11] = 0;
        var prior = query[^38..^6];
        var input = new byte[] { 0, 32 }.Concat(prior).Concat(unsigned).Concat(KeyName).Concat(new byte[] { 0, 255, 0, 0, 0, 0 }).Concat(Algorithm).Concat(timers).Concat(new byte[4]).ToArray();
        var offset = data + Algorithm.Length + 10;
        Assert.Equal(HMACSHA256.HashData(Secret, input), response.AsSpan(offset, 32).ToArray()); Assert.Equal(new byte[] { 0xbe, 0xef, 0, 0, 0, 0 }, response[^6..]);
    }

    private static byte[] Timers()
    {
        var bytes = new byte[8]; var time = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)(time >> 32)); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(2), (uint)time); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 300); return bytes;
    }

    private static void WriteKeys(string path)
    {
        var origin = DnsName.Parse("example.").ToWire();
        var data = new byte[] { 1, 1, 0, (byte)KeyName.Length }.Concat(KeyName).Concat(new byte[] { 16, 32 }).Concat(Secret).Concat(new byte[] { 1, 0, (byte)origin.Length }).Concat(origin).Concat(new byte[] { 2, 4, 127, 0, 0, 1, 16 }).Concat(IPAddress.IPv6Loopback.GetAddressBytes()).ToArray();
        File.WriteAllBytes(path, data);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static async Task SeedAsync(string state, Guid id)
    {
        var origin = DnsName.Parse("example.");
        var soa = DnsName.Parse("ns.example.").ToWire().Concat(DnsName.Parse("hostmaster.example.").ToWire()).Concat(new byte[20]).ToArray(); BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(soa.Length - 20), 1);
        var records = new DnsRecord[] { new(origin, 6, 300, soa), new(origin, 2, 300, DnsName.Parse("ns.example.").ToWire()), new(DnsName.Parse("www.example."), 1, 300, [192, 0, 2, 42]) };
        var store = new FileZoneSnapshotStore(state);
        await using (store.ConfigureAwait(true)) await store.ActivateAsync(ZoneBundleCodec.Compile(id, 1, new AuthoritativeZone(origin, records)), CancellationToken.None).ConfigureAwait(true);
    }

    private static int Port(IPAddress address)
    {
        using var listener = new TcpListener(address, 0); listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task HealthyAsync(int health, HostProcess application, HostProcess gateway, CancellationToken token)
    {
        using var handler = new SocketsHttpHandler { UseProxy = false }; using var http = new HttpClient(handler);
        var endpoint = new Uri(FormattableString.Invariant($"http://127.0.0.1:{health}/health/ready"));
        while (true)
        {
            Assert.False(application.HasExited); Assert.False(gateway.HasExited);
            try
            {
                using var response = await http.GetAsync(endpoint, token).ConfigureAwait(true); if (response.IsSuccessStatusCode) return;
            }
            catch (HttpRequestException) { }
            await Task.Delay(30, token).ConfigureAwait(true);
        }
    }
}
