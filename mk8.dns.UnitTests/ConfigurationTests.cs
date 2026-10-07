using Mk8.Dns.Configuration;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ConfigurationTests
{
    [Fact]
    public void CookieSecretInputsAreExplicitPrivateReplicaInputs()
    {
        var replica = new[] { "--socket", "/tmp/app.sock", "--state", "/tmp/state", "--node", "node1", "--role", "authoritative-replica" };
        Assert.Null(ApplicationSettings.Parse(replica).CookieSecretFile);
        Assert.Equal("/tmp/cookies.key", ApplicationSettings.Parse([.. replica, "--cookie-secret-file", "/tmp/cookies.key"]).CookieSecretFile);
        Assert.Throws<ArgumentException>(() => ApplicationSettings.Parse([.. replica, "--cookie-secret-file", "relative.key"]));
        Assert.Throws<ArgumentException>(() => ApplicationSettings.Parse(["--socket", "/tmp/app.sock", "--state", "/tmp/state", "--node", "node1", "--role", "controller", "--cookie-secret-file", "/tmp/cookies.key"]));
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "/tmp/app.sock", "--health-port", "8080", "--cookie-secret-file", "/tmp/cookies.key"]));
    }

    [Fact]
    public void ManagementGatewayRequiresAnIsolatedPrivateRole()
    {
        var settings = GatewaySettings.Parse(["--role", "management", "--socket", "/tmp/controller.sock", "--management-socket", "/tmp/api.sock"]);
        Assert.Equal(GatewayRole.Management, settings.Role);
        Assert.Equal(0, settings.HealthPort);
        Assert.Null(settings.DnsEndpoint);
        Assert.Equal("/tmp/api.sock", settings.ManagementSocketPath);
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--role", "management", "--socket", "/tmp/a.sock", "--management-socket", "/tmp/sub/../a.sock"]));
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--role", "management", "--socket", "/tmp/a.sock", "--management-socket", "/tmp/b.sock", "--health-port", "8080"]));
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--role", "management", "--socket", "/tmp/a.sock", "--management-socket", "/tmp/b.sock", "--dns-address", "127.0.0.2", "--dns-port", "5353"]));
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--socket", "/tmp/a.sock", "--management-socket", "/tmp/b.sock", "--health-port", "8080"]));
        Assert.Throws<ArgumentException>(() => GatewaySettings.Parse(["--role", "management", "--socket", "/tmp/a.sock"]));
        Assert.Equal(GatewayRole.Query, GatewaySettings.Parse(["--socket", "/tmp/a.sock", "--health-port", "8080"]).Role);
    }

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
