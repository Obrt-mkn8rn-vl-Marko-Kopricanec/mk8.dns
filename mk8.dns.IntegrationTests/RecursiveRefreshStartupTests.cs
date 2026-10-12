using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class RecursiveRefreshStartupTests
{
    [Theory]
    [InlineData("missing", "Every recursive", false)]
    [InlineData("unknown", "Unknown or duplicate", false)]
    [InlineData("duplicate", "Unknown or duplicate", false)]
    [InlineData("short", "bound is invalid", false)]
    [InlineData("retry", "retryInterval", false)]
    [InlineData("attempts", "bound is invalid", false)]
    [InlineData("capacity", "room for every", false)]
    [InlineData("capacity", "room for every", true)]
    [InlineData("legacy", "Unknown or duplicate", false)]
    public async Task ExplicitRefreshPolicyRefusesBeforeBindingAndPreservesJournal(string input, string reason, bool retention)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (udp, tcp) = DnssecUpstreamFixture.BindPair(ipv6: false);
        using var udpLifetime = udp; using var tcpLifetime = tcp;
        using var fixture = new RecursiveStartupFixture(DnssecUpstreamFixture.Endpoint(udp).Port, 53, retention: retention);
        var policy = Policy(); fixture.Configuration["refreshPolicy"] = policy;
        switch (input)
        {
            case "missing": _ = fixture.Configuration.Remove("refreshPolicy"); break;
            case "unknown": policy["unbounded"] = true; break;
            case "short": policy["refreshIntervalSeconds"] = 3599; break;
            case "retry": policy["retryIntervalSeconds"] = 7200; break;
            case "attempts": policy["maximumAttempts"] = 0; break;
            case "capacity": policy["maximumAttempts"] = 256; break;
        }
        var text = fixture.Configuration.ToJsonString();
        fixture.Write(string.Equals(input, "duplicate", StringComparison.Ordinal)
            ? text.Replace("\"maximumAttempts\":1", "\"maximumAttempts\":1,\"maximumAttempts\":1", StringComparison.Ordinal) : text);
        var before = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var path in Directory.GetFiles(fixture.StorePath))
            before.Add(Path.GetFileName(path), await File.ReadAllBytesAsync(path, guard.Token).ConfigureAwait(true));
        var host = new HostProcess("mk8.dns.Application",
            [string.Equals(input, "legacy", StringComparison.Ordinal) ? "--recursive-config" : "--recursive-refresh-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        await host.WaitForExitAsync(guard.Token).ConfigureAwait(true);
        Assert.NotEqual(0, host.ExitCode);
        Assert.Contains(reason, await host.ReadLogsAsync(guard.Token).ConfigureAwait(true), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(before.Count, Directory.GetFiles(fixture.StorePath).Length);
        foreach (var path in Directory.GetFiles(fixture.StorePath))
            Assert.Equal(before[Path.GetFileName(path)], await File.ReadAllBytesAsync(path, guard.Token).ConfigureAwait(true));
        fixture.AssertStoreReopens(retention);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FiniteRefreshModeWaitsBeforeAcquisitionAndSignalDrainsTimerBeforeLeaseRelease(bool retention)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = Assert.IsType<IPEndPoint>(upstream.Client.LocalEndPoint);
        var port = RecursiveStartupFixture.VacantPair();
        using var fixture = new RecursiveStartupFixture(port, endpoint.Port, retention: retention);
        fixture.Configuration["refreshPolicy"] = Policy(); fixture.Write();
        var host = new HostProcess("mk8.dns.Application", ["--recursive-refresh-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        using var peer = await ConnectAsync(port, host, guard.Token).ConfigureAwait(true);
        Assert.Equal(0, upstream.Available);
        await host.StopAsync(guard.Token).ConfigureAwait(true);
        Assert.Equal(0, host.ExitCode); Assert.Equal(0, upstream.Available);
        fixture.AssertStoreReopens(retention);
    }

    private static JsonObject Policy() => new()
    {
        ["refreshIntervalSeconds"] = 3600,
        ["retryIntervalSeconds"] = 3600,
        ["maximumAttempts"] = 1,
    };

    private static async Task<TcpClient> ConnectAsync(int port, HostProcess host, CancellationToken token)
    {
        while (!host.HasExited)
        {
            var peer = new TcpClient(AddressFamily.InterNetwork);
            try { await peer.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(true); return peer; }
            catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionRefused)
            {
                peer.Dispose(); await Task.Delay(TimeSpan.FromMilliseconds(10), token).ConfigureAwait(true);
            }
            catch { peer.Dispose(); throw; }
        }
        throw new IOException("Owned finite refresh startup exited before binding: " + await host.ReadLogsAsync(token).ConfigureAwait(true));
    }
}
