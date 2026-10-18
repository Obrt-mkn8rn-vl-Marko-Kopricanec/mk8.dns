using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class GatewayDnsPolicyStartupTests
{
    [Theory]
    [InlineData("{\"TcpConnections\":17,\"MessagesPerConnection\":1,\"FrameTimeoutMilliseconds\":2000}", "SecretDnsPolicyBounds")]
    [InlineData("{\"TcpConnections\":1,\"MessagesPerConnection\":1}", "SecretDnsPolicyInvalid")]
    [InlineData("{\"TcpConnections\":1,\"MessagesPerConnection\":1,\"FrameTimeoutMilliseconds\":2000,\"PROTECTED_SENTINEL\":true}", "SecretDnsPolicyInvalid")]
    public async Task InvalidPolicyRefusesBeforeOwnedEndpointAcquisition(string policy, string reason)
    {
        using var health = new TcpListener(IPAddress.Loopback, 0); health.Start(1);
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var dns = Assert.IsType<IPEndPoint>(udp.Client.LocalEndPoint);
        using var tcp = new TcpListener(dns); tcp.Start(1);
        var healthPort = ((IPEndPoint)health.LocalEndpoint).Port;
        var missing = Path.Combine(Path.GetTempPath(), "m8-policy-" + Guid.NewGuid().ToString("N") + ".sock");
        var host = new HostProcess("mk8.dns.Gateway",
            ["--socket", missing, "--role", "query", "--health-port", healthPort.ToString(CultureInfo.InvariantCulture),
                "--dns-address", "127.0.0.1", "--dns-port", dns.Port.ToString(CultureInfo.InvariantCulture)],
            healthPort, dnsPolicy: policy);
        await using var lifetime = host.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await host.WaitForExitAsync(deadline.Token).ConfigureAwait(true);
        var logs = await host.ReadLogsAsync(deadline.Token).ConfigureAwait(true);
        Assert.NotEqual(0, host.ExitCode);
        Assert.Contains(reason, logs, StringComparison.Ordinal);
        Assert.DoesNotContain("PROTECTED_SENTINEL", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("Address already in use", logs, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Now listening on:", logs, StringComparison.Ordinal);
        Assert.False(File.Exists(missing));
    }
}
