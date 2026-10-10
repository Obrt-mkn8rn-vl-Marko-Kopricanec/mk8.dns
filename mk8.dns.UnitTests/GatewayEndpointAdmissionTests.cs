using System.Globalization;
using System.Net;
using Mk8.Dns.Configuration;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class GatewayEndpointAdmissionTests
{
    [Theory]
    [InlineData("127.0.0.1", 1024)]
    [InlineData("127.0.0.1", 8080)]
    [InlineData("127.0.0.1", 65535)]
    [InlineData("127.1", 8080)]
    public void SameIpv4HealthEndpointRefusesBeforeHostStartup(string address, int port)
    {
        var error = Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(Arguments(address, port, port)));
        Assert.Equal("args", error.ParamName);
    }

    [Theory]
    [InlineData("127.0.0.1", 8081, 8080)]
    [InlineData("127.0.0.2", 8080, 8080)]
    [InlineData("::1", 8080, 8080)]
    [InlineData("192.0.2.1", 8080, 8080)]
    public void DistinctEndpointRemainsCallerConfigured(string address, int dnsPort, int healthPort)
    {
        // Loopback and reserved documentation addresses are finite parser fixtures, never allocations.
        var settings = GatewaySettings.Parse(Arguments(address, dnsPort, healthPort));
        Assert.Equal(new IPEndPoint(IPAddress.Parse(address), dnsPort), settings.DnsEndpoint);
        Assert.Equal(healthPort, settings.HealthPort);
    }

    private static string[] Arguments(string address, int dnsPort, int healthPort)
        => ["--socket", "/tmp/endpoint-fixture.sock", "--health-port", healthPort.ToString(CultureInfo.InvariantCulture),
            "--dns-address", address, "--dns-port", dnsPort.ToString(CultureInfo.InvariantCulture)];
}
