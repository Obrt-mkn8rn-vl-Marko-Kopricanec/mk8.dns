using System.Net;
using System.Net.Sockets;
using System.Text;
using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class IpcPreflightTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidApplicationPathCannotCreateManagementSocketState(bool multibyte)
    {
        using var fixture = new Fixture();
        var application = fixture.InvalidPath(multibyte);
        var runtime = Path.Combine(fixture.Root, "run");
        var management = Path.Combine(runtime, "management.sock");
        await HostProcessScope.RunAsync(() => new HostProcess("mk8.dns.Gateway",
            ["--socket", application, "--role", "management", "--management-socket", management], 0), async host =>
        {
            var logs = await RefusalAsync(host).ConfigureAwait(true);
            Assert.DoesNotContain(application, logs, StringComparison.Ordinal);
            Assert.False(Directory.Exists(runtime));
            Assert.False(File.Exists(management));
            Assert.False(File.Exists(management + ".lock"));
        }).ConfigureAwait(true);
    }

    [Fact]
    public async Task InvalidOperatorPathRefusesBeforeMissingRequestAndCredentialValues()
    {
        using var fixture = new Fixture();
        await HostProcessScope.RunAsync(() => new HostProcess("mk8.dns.Operator", ["--socket", fixture.InvalidPath(multibyte: false),
            "--request-secret", "AbsentRequest", "--credential-secret", "AbsentCredential"], 0), async host =>
        {
            var logs = await RefusalAsync(host).ConfigureAwait(true);
            Assert.DoesNotContain("SecretValueMissingOrOversized", logs, StringComparison.Ordinal);
            Assert.DoesNotContain("SecretManagementRequestInvalid", logs, StringComparison.Ordinal);
        }).ConfigureAwait(true);
    }

    [Fact]
    public async Task ValidManagementPathBindsAndReleasesItsOwnedLeaseWithoutABackend()
    {
        using var fixture = new Fixture();
        var management = Path.Combine(fixture.Root, "run", "management.sock");
        await HostProcessScope.RunAsync(() => new HostProcess("mk8.dns.Gateway", ["--socket", Path.Combine(fixture.Root, "absent.sock"),
            "--role", "management", "--management-socket", management], 0), async host =>
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var handler = Handler(management);
            using var client = new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri("http://localhost") };
            await LiveAsync(client, host, deadline.Token).ConfigureAwait(true);
            Assert.True(File.Exists(management + ".lock"));
            await host.StopAsync(deadline.Token).ConfigureAwait(true);
            Assert.Equal(0, host.ExitCode);
            using var reopened = new PrivateUnixSocket(management);
            Assert.Equal(management, reopened.Path);
        }).ConfigureAwait(true);
    }

    private static async Task<string> RefusalAsync(HostProcess host)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await host.WaitForExitAsync(deadline.Token).ConfigureAwait(true);
        var logs = await host.ReadLogsAsync(deadline.Token).ConfigureAwait(true);
        Assert.NotEqual(0, host.ExitCode);
        Assert.Contains("Use an absolute Unix socket path of at most 100 UTF-8 bytes.", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("Now listening on:", logs, StringComparison.Ordinal);
        return logs;
    }

    private static SocketsHttpHandler Handler(string path) => new()
    {
        UseProxy = false,
        ConnectCallback = async (_, token) =>
        {
            var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), token).ConfigureAwait(true);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch { socket.Dispose(); throw; }
        },
    };

    private static async Task LiveAsync(HttpClient client, HostProcess host, CancellationToken token)
    {
        while (true)
        {
            Assert.False(host.HasExited);
            try
            {
                using var response = await client.GetAsync(new Uri("/health/live", UriKind.Relative), token).ConfigureAwait(true);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                return;
            }
            catch (HttpRequestException) { }
            await Task.Delay(20, token).ConfigureAwait(true);
        }
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "m8pre-" + Guid.NewGuid().ToString("N"));
        internal Fixture()
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            Directory.CreateDirectory(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        internal string InvalidPath(bool multibyte)
        {
            var path = Path.Combine(Root, new string(multibyte ? 'é' : 'x', multibyte ? 30 : 101) + ".sock");
            Assert.True(Encoding.UTF8.GetByteCount(path) > 100);
            if (multibyte) Assert.True(path.Length <= 100);
            return path;
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
