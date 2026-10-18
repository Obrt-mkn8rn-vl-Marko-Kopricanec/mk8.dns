using System.Text.Json;
using System.Text.Json.Nodes;
using Mk8.Dns.Configuration;
using Supprocom.Secrets;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class GatewayDnsPolicyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QuerySnapshotUsesCompletePolicyOrExistingSoftwareCeilings(bool supplied)
    {
        using var fixture = new Fixture();
        var snapshot = await fixture.LoadAsync(supplied ? Policy().ToJsonString() : null).ConfigureAwait(true);
        Assert.NotNull(GatewaySettings.FromSecrets(snapshot).DnsEndpoint);
        var policy = GatewayDnsPolicy.FromSecrets(snapshot);
        Assert.Equal(supplied ? 2 : 16, policy.TcpConnections);
        Assert.Equal(supplied ? 3 : 100, policy.MessagesPerConnection);
        Assert.Equal(supplied ? 50 : 2000, policy.FrameTimeoutMilliseconds);
    }

    [Theory]
    [InlineData("TcpConnections", 0)]
    [InlineData("TcpConnections", 17)]
    [InlineData("MessagesPerConnection", 0)]
    [InlineData("MessagesPerConnection", 101)]
    [InlineData("FrameTimeoutMilliseconds", 0)]
    [InlineData("FrameTimeoutMilliseconds", 2001)]
    public async Task ExplicitLimitsCannotBroadenOrDisableExistingBounds(string field, int value)
    {
        using var fixture = new Fixture();
        var input = Policy(); input[field] = value;
        var snapshot = await fixture.LoadAsync(input.ToJsonString()).ConfigureAwait(true);
        var error = Assert.Throws<InvalidDataException>(() => GatewayDnsPolicy.FromSecrets(snapshot));
        Assert.Equal("SecretDnsPolicyBounds", error.Message);
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("missing")]
    [InlineData("type")]
    [InlineData("unknown")]
    public async Task SuppliedSchemaIsCompleteClosedAndValueFreeOnRefusal(string defect)
    {
        using var fixture = new Fixture();
        var input = Policy();
        switch (defect)
        {
            case "missing": Assert.True(input.Remove("TcpConnections")); break;
            case "type": input["TcpConnections"] = "PROTECTED_SENTINEL"; break;
            case "unknown": input["PROTECTED_SENTINEL"] = true; break;
        }
        var snapshot = await fixture.LoadAsync(string.Equals(defect, "null", StringComparison.Ordinal) ? "null" : input.ToJsonString()).ConfigureAwait(true);
        var error = Assert.Throws<InvalidDataException>(() => GatewayDnsPolicy.FromSecrets(snapshot));
        Assert.Equal("SecretDnsPolicyInvalid", error.Message);
        Assert.DoesNotContain("PROTECTED_SENTINEL", error.ToString(), StringComparison.Ordinal);
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RolesWithoutDnsAdmissionRefuseTheExtraSetting(bool management)
    {
        using var fixture = new Fixture();
        var snapshot = await fixture.LoadAsync(Policy().ToJsonString(), management, dns: false).ConfigureAwait(true);
        var error = Assert.Throws<InvalidDataException>(() => GatewaySettings.FromSecrets(snapshot));
        Assert.Equal("SecretSettingUnknown", error.Message);
    }

    private static JsonObject Policy() => new()
    {
        ["TcpConnections"] = 2,
        ["MessagesPerConnection"] = 3,
        ["FrameTimeoutMilliseconds"] = 50,
    };

    private sealed class Fixture : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "m8-dns-policy-" + Guid.NewGuid().ToString("N"));
        internal Fixture() => Directory.CreateDirectory(root);

        internal async Task<DnsServiceSecrets> LoadAsync(string? policy, bool management = false, bool dns = true)
        {
            List<string> settings = ["--socket", Path.Combine(root, "app.sock"), "--role", management ? "management" : "query"];
            if (management) settings.AddRange(["--management-socket", Path.Combine(root, "management.sock")]);
            else settings.AddRange(["--health-port", "5355"]);
            if (dns) settings.AddRange(["--dns-address", "127.0.0.1", "--dns-port", "5300"]);
            List<SupprocomSecretSetting> values = [new("Gateway:Settings", JsonSerializer.Serialize(settings))];
            if (policy is not null) values.Add(new SupprocomSecretSetting("Gateway:DnsPolicy", policy));
            await File.WriteAllTextAsync(Path.Combine(root, ".env"), SupprocomSecretDocument.Serialize(values), CancellationToken.None).ConfigureAwait(true);
            return await DnsServiceSecrets.LoadDirectoryAsync("Gateway", root, CancellationToken.None).ConfigureAwait(true);
        }

        public void Dispose() => Directory.Delete(root, recursive: true);
    }
}
