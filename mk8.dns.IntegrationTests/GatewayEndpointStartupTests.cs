using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class GatewayEndpointStartupTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.1")]
    public async Task ConflictRefusesBeforeConnectingOrBindingWithOwnedPortsAlreadyHeld(string address)
    {
        // These are owned loopback sentinels, not deployment allocations or foreign-port probes.
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udp.Bind(new IPEndPoint(IPAddress.Loopback, port));
        var missingSocket = Path.Combine(Path.GetTempPath(), "m8-endpoint-" + Guid.NewGuid().ToString("N") + ".sock");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var host = new HostProcess("mk8.dns.Gateway", ["--socket", missingSocket, "--health-port", port.ToString(CultureInfo.InvariantCulture),
            "--dns-address", address, "--dns-port", port.ToString(CultureInfo.InvariantCulture)], port);
        await using (host.ConfigureAwait(true))
        {
            while (!host.HasExited)
                await Task.Delay(10, timeout.Token).ConfigureAwait(true);
            var logs = await host.ReadLogsAsync(timeout.Token).ConfigureAwait(true);
            Assert.NotEqual(0, host.ExitCode);
            Assert.Contains("DNS TCP and loopback health require distinct bind endpoints.", logs, StringComparison.Ordinal);
            Assert.DoesNotContain("Address already in use", logs, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Now listening on:", logs, StringComparison.Ordinal);
            Assert.False(File.Exists(missingSocket));
            Assert.Equal(port, ((IPEndPoint)udp.LocalEndPoint!).Port);
            Assert.Equal(port, ((IPEndPoint)tcp.LocalEndpoint).Port);
        }
    }
}
