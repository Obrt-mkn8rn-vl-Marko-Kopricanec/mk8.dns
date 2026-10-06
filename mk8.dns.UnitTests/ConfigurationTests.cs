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
}
