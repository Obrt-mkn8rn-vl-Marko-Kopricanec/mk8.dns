using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using Grpc.Core;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class HostBoundaryTests
{
    [Fact]
    public async Task SeparateHostsRecoverLocalStateAfterApplicationLossWithoutClaimingDnsReadiness()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8dns-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var socket = Path.Combine(root, "run", "app.sock");
            var state = Path.Combine(root, "state");
            using (var seed = new FileZoneSnapshotStore(state))
                await seed.ActivateAsync(new ZoneSnapshot(Guid.NewGuid(), DnsName.Parse("example.org."), 1, 1, [1, 2, 3]), CancellationToken.None).ConfigureAwait(true);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = timeout.Token;
            var applicationArguments = new[] { "--socket", socket, "--state", state, "--node", "test-node", "--role", "authoritative-replica" };
            var injectedPort = AvailablePort();
            var application = new HostProcess("mk8.dns.Application", applicationArguments, injectedPort);
            await using (application.ConfigureAwait(true))
            {
                using var local = new UnixApplicationClient(socket);
                await WaitUntilAsync(async () =>
                {
                    try
                    {
                        var status = await local.GetStatusAsync(ProtocolVersion.Current, token).ConfigureAwait(true);
                        return status.ActiveSnapshots == 1 && !status.DnsReady;
                    }
                    catch (RpcException)
                    {
                        Assert.False(application.HasExited);
                        return false;
                    }
                }, token).ConfigureAwait(true);
                await AssertApplicationBoundaryAsync(local, socket, injectedPort, token).ConfigureAwait(true);

                var port = AvailablePort();
                var gateway = new HostProcess("mk8.dns.Gateway", ["--socket", socket, "--health-port", port.ToString(System.Globalization.CultureInfo.InvariantCulture)], injectedPort);
                await using (gateway.ConfigureAwait(true))
                {
                    using var handler = new SocketsHttpHandler { UseProxy = false };
                    using var http = new HttpClient(handler) { BaseAddress = new Uri(FormattableString.Invariant($"http://127.0.0.1:{port}")), Timeout = TimeSpan.FromSeconds(4) };
                    await AssertGatewayAndRestartAsync(http, gateway, application, applicationArguments, injectedPort, token).ConfigureAwait(true);
                }
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void SocketLeaseProtectsActiveOwnershipAndExistingFiles()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8dns-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var path = Path.Combine(root, "app.sock");
            using (var lease = new PrivateUnixSocket(path))
                Assert.Throws<IOException>(() => new PrivateUnixSocket(path));
            File.WriteAllText(path, "preserve");
            Assert.Throws<IOException>(() => new PrivateUnixSocket(path));
            Assert.Equal("preserve", File.ReadAllText(path));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }


    private static async Task AssertApplicationBoundaryAsync(UnixApplicationClient local, string socket, int injectedPort, CancellationToken token)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var mode = File.GetUnixFileMode(socket);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite, mode);
        using (var denied = new TcpClient())
            await Assert.ThrowsAsync<SocketException>(() => denied.ConnectAsync(IPAddress.Loopback, injectedPort, token).AsTask()).ConfigureAwait(true);
        var wrongVersion = await Assert.ThrowsAsync<RpcException>(() => local.GetStatusAsync(ProtocolVersion.Current + 1, token)).ConfigureAwait(true);
        Assert.Equal(StatusCode.FailedPrecondition, wrongVersion.StatusCode);

    }

    private static async Task AssertGatewayAndRestartAsync(HttpClient http, HostProcess gateway, HostProcess application, string[] applicationArguments, int injectedPort, CancellationToken token)
    {
        await WaitUntilAsync(async () =>
        {
            try
            {
                using var response = await http.GetAsync(new Uri("/health/application", UriKind.Relative), token).ConfigureAwait(true);
                return response.StatusCode == HttpStatusCode.OK;
            }
            catch (HttpRequestException)
            {
                Assert.False(gateway.HasExited);
                return false;
            }
        }, token).ConfigureAwait(true);
        using (var ready = await http.GetAsync(new Uri("/health/ready", UriKind.Relative), token).ConfigureAwait(true))
            Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        var healthy = await http.GetFromJsonAsync<ApplicationStatus>("/health/application", token).ConfigureAwait(true);
        Assert.NotNull(healthy);
        Assert.Equal("test-node", healthy.NodeId);
        Assert.Equal(1u, healthy.ActiveSnapshots);
        Assert.False(healthy.DnsReady);
        using (var denied = new TcpClient())
            await Assert.ThrowsAsync<SocketException>(() => denied.ConnectAsync(IPAddress.Loopback, injectedPort, token).AsTask()).ConfigureAwait(true);

        await application.KillAsync(token).ConfigureAwait(true);
        await WaitUntilAsync(async () =>
        {
            using var response = await http.GetAsync(new Uri("/health/application", UriKind.Relative), token).ConfigureAwait(true);
            return response.StatusCode == HttpStatusCode.ServiceUnavailable;
        }, token).ConfigureAwait(true);
        using (var live = await http.GetAsync(new Uri("/health/live", UriKind.Relative), token).ConfigureAwait(true))
            Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.False(gateway.HasExited);

        var restarted = new HostProcess("mk8.dns.Application", applicationArguments, injectedPort);
        await using (restarted.ConfigureAwait(true))
        {
            await WaitUntilAsync(async () =>
            {
                using var response = await http.GetAsync(new Uri("/health/application", UriKind.Relative), token).ConfigureAwait(true);
                return response.StatusCode == HttpStatusCode.OK;
            }, token).ConfigureAwait(true);
            var recovered = await http.GetFromJsonAsync<ApplicationStatus>("/health/application", token).ConfigureAwait(true);
            Assert.NotNull(recovered);
            Assert.Equal(1u, recovered.ActiveSnapshots);
            Assert.False(recovered.DnsReady);
        }
    }

    private static int AvailablePort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private static async Task WaitUntilAsync(Func<Task<bool>> predicate, CancellationToken token)
    {
        while (!await predicate().ConfigureAwait(true))
            await Task.Delay(TimeSpan.FromMilliseconds(50), token).ConfigureAwait(true);
    }

}
