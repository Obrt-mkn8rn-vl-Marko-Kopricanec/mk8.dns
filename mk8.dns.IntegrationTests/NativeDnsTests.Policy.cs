using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed partial class NativeDnsTests
{
    [Fact]
    public async Task QueryGatewayUsesTheProtectedMessageLimitAndKeepsUdpServing()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8-gateway-policy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try { await RunLimitedGatewayAsync(root).ConfigureAwait(true); }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static async Task RunLimitedGatewayAsync(string root)
    {
        var id = Guid.NewGuid();
        var state = Path.Combine(root, "state");
        await SeedAsync(state, id).ConfigureAwait(true);
        var socket = Path.Combine(root, "run", "app.sock");
        var health = Port();
        var dns = Port();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var token = deadline.Token;
        var application = new HostProcess("mk8.dns.Application",
            ["--socket", socket, "--state", state, "--node", "policy-test", "--role", "authoritative-replica", "--zones", id.ToString("N")], Port());
        await using var applicationLifetime = application.ConfigureAwait(true);
        var gateway = new HostProcess("mk8.dns.Gateway",
            ["--socket", socket, "--health-port", health.ToString(CultureInfo.InvariantCulture), "--dns-address", "127.0.0.1", "--dns-port", dns.ToString(CultureInfo.InvariantCulture)],
            Port(), dnsPolicy: "{\"TcpConnections\":1,\"MessagesPerConnection\":1,\"FrameTimeoutMilliseconds\":2000}");
        await using var gatewayLifetime = gateway.ConfigureAwait(true);
        using var handler = new SocketsHttpHandler { UseProxy = false };
        using var http = new HttpClient(handler) { BaseAddress = new Uri(string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{health}")) };
        await HealthyAsync(http, application, gateway, token).ConfigureAwait(true);
        await AssertSingleFrameAndUdpAsync(dns, token).ConfigureAwait(true);
        await gateway.StopAsync(token).ConfigureAwait(true);
        Assert.Equal(0, gateway.ExitCode);
        await application.StopAsync(token).ConfigureAwait(true);
        Assert.Equal(0, application.ExitCode);
    }

    private static async Task AssertSingleFrameAndUdpAsync(int port, CancellationToken token)
    {
        var query = Convert.FromHexString("abcd0100000100000000000003777777076578616d706c650000010001");
        using var client = new TcpClient(AddressFamily.InterNetwork);
        await client.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(true);
        var stream = client.GetStream();
        await using var streamLifetime = stream.ConfigureAwait(true);
        var frame = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)query.Length); query.CopyTo(frame, 2);
        await stream.WriteAsync(frame, token).ConfigureAwait(true);
        var prefix = new byte[2];
        await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(true);
        var answer = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
        await stream.ReadExactlyAsync(answer, token).ConfigureAwait(true);
        AssertAnswer(answer, query);
        await AssertClosedOnNextMessageAsync(stream, frame, token).ConfigureAwait(true);
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        _ = await udp.SendAsync(query, new IPEndPoint(IPAddress.Loopback, port), token).ConfigureAwait(true);
        AssertAnswer((await udp.ReceiveAsync(token).ConfigureAwait(true)).Buffer, query);
    }

    private static async Task AssertClosedOnNextMessageAsync(NetworkStream stream, byte[] frame, CancellationToken token)
    {
        try
        {
            await stream.WriteAsync(frame, token).ConfigureAwait(true);
            Assert.Equal(0, await stream.ReadAsync(new byte[1], token).ConfigureAwait(true));
        }
        catch (IOException error) when (error.InnerException is SocketException socket
            && socket.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.Shutdown)
        { }
    }
}
