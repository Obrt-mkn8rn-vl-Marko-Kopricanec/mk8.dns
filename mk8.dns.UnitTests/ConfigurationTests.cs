using Mk8.Dns.Configuration;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ConfigurationTests
{
    [Theory]
    [InlineData("resolver")]
    [InlineData("all")]
    [InlineData("Controller")]
    public void UnsupportedOrImplicitRolesAreRejected(string role) => Assert.Throws<ArgumentException>(() => ApplicationSettings.Parse(["--socket", "/tmp/app.sock", "--state", "/tmp/state", "--node", "node1", "--role", role]));

    [Theory]
    [InlineData("0")]
    [InlineData("53")]
    [InlineData("65536")]
    [InlineData("-1")]
    [InlineData(" 8080")]
    public void HealthPortMustBeExplicitAndUnprivileged(string port) => Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--health-port", port]));

    [Fact]
    public void HostArgumentsCannotOverrideListenersOrDuplicateSettings()
    {
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--health-port", "8080", "--urls", "http://0.0.0.0:53"]));
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--socket", "/tmp/other.sock", "--health-port", "8080"]));
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "relative.sock", "--health-port", "8080"]));
        Assert.Throws<ArgumentException>(() => ApplicationSettings.Parse(["--socket", "/tmp/app.sock", "--state", "/tmp/state", "--node", "node1"]));
    }

    [Fact]
    public void DnsListenersRequireExplicitAddressAndPortAndZonesRequireReplicaRole()
    {
        Assert.Null(GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--health-port", "8080"]).DnsEndpoint);
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--health-port", "8080", "--dns-port", "5353"]));
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--health-port", "8080", "--dns-address", "localhost", "--dns-port", "5353"]));
        var id = Guid.NewGuid().ToString("N");
        Assert.Throws<ArgumentException>(() => ApplicationSettings.Parse(["--socket", "/tmp/app.sock", "--state", "/tmp/state", "--node", "node1", "--role", "controller", "--zones", id]));
        Assert.Throws<ArgumentException>(() => ApplicationSettings.Parse(["--socket", "/tmp/app.sock", "--state", "/tmp/state", "--node", "node1", "--role", "authoritative-replica", "--zones", id + "," + id]));
        Assert.Single(ApplicationSettings.Parse(["--socket", "/tmp/app.sock", "--state", "/tmp/state", "--node", "node1", "--role", "authoritative-replica", "--zones", id]).ZoneIds);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("::%1")]
    [InlineData("::ffff:0.0.0.0")]
    public void DnsWildcardAddressesAreRejected(string address) => Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--health-port", "8080", "--dns-address", address, "--dns-port", "5353"]));

    [Theory]
    [InlineData("127.0.0.2")]
    [InlineData("::1")]
    public void SpecificDnsAddressesRemainAccepted(string address) => Assert.Equal(System.Net.IPAddress.Parse(address), GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--health-port", "8080", "--dns-address", address, "--dns-port", "5353"]).DnsEndpoint!.Address);
}
