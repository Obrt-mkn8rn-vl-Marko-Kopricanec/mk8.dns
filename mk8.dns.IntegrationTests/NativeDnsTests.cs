using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class NativeDnsTests
{
    [Fact]
    public async Task NativeUdpTcpAndRestartUseDurableLocalZonesAcrossSeparateHosts()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8dns-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            await RunPairAsync(root).ConfigureAwait(true);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RunPairAsync(string root)
    {
        var id = Guid.NewGuid();
        var state = Path.Combine(root, "state");
        await SeedAsync(state, id).ConfigureAwait(true);
        var endpoint = Path.Combine(root, "run", "app.sock");
        var arguments = new[] { "--socket", endpoint, "--state", state, "--node", "native-test", "--role", "authoritative-replica", "--zones", id.ToString("N") };
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var token = timeout.Token;
        var health = Port();
        var dns = Port();
        var application = new HostProcess("mk8.dns.Application", arguments, Port());
        await using (application.ConfigureAwait(true))
        {
            var gateway = new HostProcess("mk8.dns.Gateway", ["--socket", endpoint, "--health-port", health.ToString(CultureInfo.InvariantCulture), "--dns-address", "127.0.0.1", "--dns-port", dns.ToString(CultureInfo.InvariantCulture)], Port());
            await using (gateway.ConfigureAwait(true))
            {
                using var handler = new SocketsHttpHandler { UseProxy = false };
                using var http = new HttpClient(handler) { BaseAddress = new Uri(FormattableString.Invariant($"http://127.0.0.1:{health}")) };
                await HealthyAsync(http, application, gateway, token).ConfigureAwait(true);
                await AssertQueryProtocolRejectedAsync(endpoint, token).ConfigureAwait(true);
                await AssertQueriesAsync(dns, token).ConfigureAwait(true);
                await application.KillAsync(token).ConfigureAwait(true);
                await AssertApplicationLostAsync(http, token).ConfigureAwait(true);
                var restarted = new HostProcess("mk8.dns.Application", arguments, Port());
                await using (restarted.ConfigureAwait(true))
                {
                    await HealthyAsync(http, restarted, gateway, token).ConfigureAwait(true);
                    await AssertQueriesAsync(dns, token).ConfigureAwait(true);
                    await gateway.StopAsync(token).ConfigureAwait(true);
                    Assert.Equal(0, gateway.ExitCode);
                    await restarted.StopAsync(token).ConfigureAwait(true);
                    Assert.Equal(0, restarted.ExitCode);
                }
            }
        }
    }

    private static async Task SeedAsync(string state, Guid id)
    {
        var origin = DnsName.Parse("example.");
        var soa = DnsName.Parse("ns.example.").ToWire().Concat(DnsName.Parse("hostmaster.example.").ToWire()).Concat(new byte[20]).ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(soa.Length - 20), 1);
        BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(soa.Length - 4), 30);
        var zone = new AuthoritativeZone(origin, [new DnsRecord(origin, 6, 300, soa), new DnsRecord(origin, 2, 300, DnsName.Parse("ns.example.").ToWire()), new DnsRecord(DnsName.Parse("www.example."), 1, 300, [192, 0, 2, 42])]);
        var store = new FileZoneSnapshotStore(state);
        await using (store.ConfigureAwait(true))
            await store.ActivateAsync(ZoneBundleCodec.Compile(id, 1, zone), CancellationToken.None).ConfigureAwait(true);
    }

    private static async Task HealthyAsync(HttpClient http, HostProcess application, HostProcess gateway, CancellationToken token)
    {
        while (true)
        {
            Assert.False(application.HasExited);
            Assert.False(gateway.HasExited);
            try
            {
                using var response = await http.GetAsync(new Uri("/health/ready", UriKind.Relative), token).ConfigureAwait(true);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    var status = await http.GetFromJsonAsync<ApplicationStatus>("/health/application", token).ConfigureAwait(true);
                    Assert.NotNull(status);
                    Assert.True(status.DnsReady);
                    Assert.Equal(1u, status.ActiveSnapshots);
                    return;
                }
            }
            catch (HttpRequestException) { }
            await Task.Delay(50, token).ConfigureAwait(true);
        }
    }

    private static async Task AssertApplicationLostAsync(HttpClient http, CancellationToken token)
    {
        while (true)
        {
            using var ready = await http.GetAsync(new Uri("/health/ready", UriKind.Relative), token).ConfigureAwait(true);
            if (ready.StatusCode == HttpStatusCode.ServiceUnavailable)
                break;
            await Task.Delay(50, token).ConfigureAwait(true);
        }
        using var live = await http.GetAsync(new Uri("/health/live", UriKind.Relative), token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
    }

    private static async Task AssertQueryProtocolRejectedAsync(string path, CancellationToken token)
    {
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellationToken).ConfigureAwait(true);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        using var http = new HttpClient(handler);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("http://localhost/mk8.dns.v1.AuthoritativeQuery/Exchange"))
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            // gRPC frame carrying protobuf protocol_version=2, without other fields.
            Content = new ByteArrayContent([0, 0, 0, 0, 2, 8, 2]),
        };
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc");
        using var response = await http.SendAsync(request, token).ConfigureAwait(true);
        _ = await response.Content.ReadAsByteArrayAsync(token).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var headers = response.Headers.TryGetValues("grpc-status", out var status) ? status : response.TrailingHeaders.GetValues("grpc-status");
        Assert.Equal("9", Assert.Single(headers));
    }

    private static async Task AssertQueriesAsync(int port, CancellationToken token)
    {
        var query = Convert.FromHexString("abcd0100000100000000000003777777076578616d706c650000010001");
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        var address = new IPEndPoint(IPAddress.Loopback, port);
        _ = await udp.SendAsync(query, address, token).ConfigureAwait(true);
        using var receive = CancellationTokenSource.CreateLinkedTokenSource(token);
        receive.CancelAfter(TimeSpan.FromSeconds(5));
        var datagram = await udp.ReceiveAsync(receive.Token).ConfigureAwait(true);
        AssertAnswer(datagram.Buffer, query);
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(true);
        using var stream = tcp.GetStream();
        var frame = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)query.Length);
        query.CopyTo(frame, 2);
        // Two requests are pipelined in one write; both framed responses must arrive.
        await stream.WriteAsync(frame.Concat(frame).ToArray(), token).ConfigureAwait(true);
        for (var count = 0; count < 2; count++)
        {
            var prefix = new byte[2];
            await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(true);
            var response = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
            await stream.ReadExactlyAsync(response, token).ConfigureAwait(true);
            AssertAnswer(response, query);
        }
        // A full-size padded EDNS query exercises the larger private RPC limit.
        var large = new byte[ushort.MaxValue];
        query.CopyTo(large, 0);
        large[11] = 1;
        var opt = query.Length;
        BinaryPrimitives.WriteUInt16BigEndian(large.AsSpan(opt + 1), 41);
        BinaryPrimitives.WriteUInt16BigEndian(large.AsSpan(opt + 3), 1232);
        BinaryPrimitives.WriteUInt16BigEndian(large.AsSpan(opt + 9), (ushort)(large.Length - opt - 11));
        BinaryPrimitives.WriteUInt16BigEndian(large.AsSpan(opt + 11), 12);
        BinaryPrimitives.WriteUInt16BigEndian(large.AsSpan(opt + 13), (ushort)(large.Length - opt - 15));
        var largePrefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(largePrefix, ushort.MaxValue);
        await stream.WriteAsync(largePrefix, token).ConfigureAwait(true);
        await stream.WriteAsync(large, token).ConfigureAwait(true);
        await stream.ReadExactlyAsync(largePrefix, token).ConfigureAwait(true);
        var largeResponse = new byte[BinaryPrimitives.ReadUInt16BigEndian(largePrefix)];
        await stream.ReadExactlyAsync(largeResponse, token).ConfigureAwait(true);
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(largeResponse.AsSpan(10)));
        Assert.Equal(new byte[] { 192, 0, 2, 42 }, largeResponse.AsSpan(query.Length + 12, 4).ToArray());
    }

    private static void AssertAnswer(byte[] response, byte[] query)
    {
        Assert.Equal(new byte[] { 0xab, 0xcd, 0x85, 0, 0, 1, 0, 1, 0, 0, 0, 0 }, response[..12]);
        Assert.Equal(query[12..], response[12..query.Length]);
        Assert.Equal(new byte[] { 192, 0, 2, 42 }, response[^4..]);
    }

    private static int Port()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
}
