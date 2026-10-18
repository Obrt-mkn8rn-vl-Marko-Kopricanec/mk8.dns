using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Grpc.Core;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class AuthorityIpcPreflightTests
{
    [Theory]
    [InlineData("main-ascii")]
    [InlineData("publication-ascii")]
    [InlineData("publication-utf8")]
    public async Task InvalidListenPathRefusesBeforeReplicaStateAndLeases(string fault)
    {
        using var fixture = new Fixture();
        var invalid = fixture.InvalidPath(fault is "publication-utf8");
        var main = fault is "main-ascii" ? invalid : fixture.Query;
        var publication = fault is "main-ascii" ? fixture.Publication : invalid;
        await HostProcessScope.RunAsync(() => new HostProcess("mk8.dns.Application",
            fixture.Arguments(main, publication, missingControl: fault is "main-ascii"), 0), async child =>
        {
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await child.WaitForExitAsync(guard.Token).ConfigureAwait(true);
            var logs = await child.ReadLogsAsync(guard.Token).ConfigureAwait(true);
            Assert.NotEqual(0, child.ExitCode);
            Assert.Contains("Use an absolute Unix socket path of at most 100 UTF-8 bytes.", logs, StringComparison.Ordinal);
            Assert.DoesNotContain(invalid, logs, StringComparison.Ordinal);
            Assert.DoesNotContain("SecretValueMissingOrOversized", logs, StringComparison.Ordinal);
            Assert.DoesNotContain("Now listening on:", logs, StringComparison.Ordinal);
            Assert.False(Directory.Exists(fixture.Runtime));
            Assert.False(Directory.Exists(fixture.State));
            Assert.False(Directory.Exists(fixture.State + ".publications"));
        }).ConfigureAwait(true);
    }

    [Fact]
    public async Task ValidReplicaStartsBothIpcHostsAndReleasesTheirStateOwners()
    {
        using var fixture = new Fixture();
        await HostProcessScope.RunAsync(() => new HostProcess("mk8.dns.Application",
            fixture.Arguments(fixture.Query, fixture.Publication), 0), async child =>
        {
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var client = new UnixApplicationClient(fixture.Query);
            var status = await StatusAsync(client, child, guard.Token).ConfigureAwait(true);
            Assert.Equal("fixture", status.NodeId);
            Assert.Equal("authoritative-replica", status.Role);
            Assert.False(status.DnsReady);
            Assert.Equal(0u, status.ActiveSnapshots);
            using (var publication = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
                await publication.ConnectAsync(new UnixDomainSocketEndPoint(fixture.Publication), guard.Token).ConfigureAwait(true);
            await child.StopAsync(guard.Token).ConfigureAwait(true);
            Assert.Equal(0, child.ExitCode);
            using var queryLease = new PrivateUnixSocket(fixture.Query);
            using var publicationLease = new PrivateUnixSocket(fixture.Publication);
            var snapshots = new FileZoneSnapshotStore(fixture.State);
            await using var lifetime = snapshots.ConfigureAwait(true);
            using var journal = new FilePublicationJournal(fixture.State + ".publications");
            Assert.Equal(0u, await snapshots.CountActiveAsync(guard.Token).ConfigureAwait(true));
        }).ConfigureAwait(true);
    }

    private static async Task<ApplicationStatus> StatusAsync(UnixApplicationClient client, HostProcess child, CancellationToken token)
    {
        while (true)
        {
            Assert.False(child.HasExited);
            try { return await client.GetStatusAsync(ProtocolVersion.Current, token).ConfigureAwait(true); }
            catch (RpcException) { }
            await Task.Delay(20, token).ConfigureAwait(true);
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "m8api-" + Guid.NewGuid().ToString("N"));
        internal string Runtime => Path.Combine(root, "run");
        internal string State => Path.Combine(root, "state");
        internal string Query => Path.Combine(Runtime, "query.sock");
        internal string Publication => Path.Combine(Runtime, "publication.sock");

        internal Fixture()
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var keyPath = Path.Combine(root, "public.pem");
                File.WriteAllText(keyPath, key.ExportSubjectPublicKeyInfoPem());
                File.WriteAllText(Path.Combine(root, "control.json"), JsonSerializer.Serialize(new
                {
                    Epoch = Guid.NewGuid(),
                    TargetNode = "fixture",
                    KeyFile = keyPath,
                    Zones = new[] { new { ZoneId = Guid.NewGuid(), Origin = "example." } },
                }));
            }
            catch { Directory.Delete(root, recursive: true); throw; }
        }

        internal string[] Arguments(string query, string publication, bool missingControl = false)
            => ["--socket", query, "--state", State, "--node", "fixture", "--role", "authoritative-replica",
                missingControl ? "--control-secret" : "--control", missingControl ? "AbsentControl" : Path.Combine(root, "control.json"),
                "--publication-socket", publication];

        internal string InvalidPath(bool multibyte)
        {
            var path = Path.Combine(root, new string(multibyte ? 'é' : 'x', multibyte ? 40 : 101) + ".sock");
            Assert.True(Encoding.UTF8.GetByteCount(path) > 100);
            if (multibyte) Assert.True(path.Length <= 100);
            return path;
        }

        public void Dispose() => Directory.Delete(root, recursive: true);
    }
}
