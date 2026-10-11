using System.Text.Json.Nodes;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class RecursiveStartupAdmissionTests
{
    [Theory]
    [InlineData("unknown", "Unknown or duplicate")]
    [InlineData("duplicate", "Unknown or duplicate")]
    [InlineData("missing", "Every recursive")]
    [InlineData("wildcard", "specific unicast")]
    [InlineData("port", "bound is invalid")]
    [InlineData("relative", "must be absolute")]
    [InlineData("egress", "explicit egress")]
    [InlineData("floor", "trusted revision floor")]
    [InlineData("key", "authentication")]
    public async Task InvalidStartupRefusesWithoutBindingOrChangingExistingStore(string input, string reason)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (heldUdp, heldTcp) = DnssecUpstreamFixture.BindPair(ipv6: false);
        using var udpLifetime = heldUdp; using var tcpLifetime = heldTcp;
        using var fixture = new RecursiveStartupFixture(DnssecUpstreamFixture.Endpoint(heldUdp).Port, 53);
        var original = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var path in Directory.GetFiles(fixture.StorePath))
            original.Add(Path.GetFileName(path), await File.ReadAllBytesAsync(path, deadline.Token).ConfigureAwait(true));
        switch (input)
        {
            case "unknown": fixture.Configuration["deploymentDefault"] = true; break;
            case "missing": _ = fixture.Configuration.Remove("clientNetworks"); break;
            case "wildcard": fixture.Configuration["listen"]!["address"] = "0.0.0.0"; break;
            case "port": fixture.Configuration["listen"]!["port"] = 0; break;
            case "relative": fixture.Configuration["storeDirectory"] = "relative"; break;
            case "egress": fixture.Configuration["egressNetworks"] = new JsonArray(); break;
            case "floor": fixture.Configuration["minimumRevision"] = 2; break;
            case "key":
                await File.WriteAllBytesAsync(fixture.Configuration["keyFile"]!.GetValue<string>(), new byte[32], deadline.Token).ConfigureAwait(true);
                break;
        }
        var text = fixture.Configuration.ToJsonString();
        fixture.Write(string.Equals(input, "duplicate", StringComparison.Ordinal) ? text.Insert(1, "\"minimumRevision\":1,") : text);
        var host = new HostProcess("mk8.dns.Application", ["--recursive-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        await host.WaitForExitAsync(deadline.Token).ConfigureAwait(true);
        var logs = await host.ReadLogsAsync(deadline.Token).ConfigureAwait(true);
        Assert.True(host.HasExited); Assert.NotEqual(0, host.ExitCode); Assert.Contains(reason, logs, StringComparison.OrdinalIgnoreCase);
        var current = Directory.GetFiles(fixture.StorePath);
        Assert.Equal(original.Count, current.Length);
        foreach (var path in current)
            Assert.Equal(original[Path.GetFileName(path)], await File.ReadAllBytesAsync(path, deadline.Token).ConfigureAwait(true));
        fixture.AssertStoreReopens(retention: false);
    }
}
