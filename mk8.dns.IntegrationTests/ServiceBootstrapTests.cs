using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ServiceBootstrapTests
{
    [Theory]
    [InlineData("publication-ascii", "Use an absolute Unix socket path of at most 100 UTF-8 bytes.")]
    [InlineData("publication-utf8", "Use an absolute Unix socket path of at most 100 UTF-8 bytes.")]
    [InlineData("database-name", "This controller profile requires one local PostgreSQL Unix socket directory.")]
    [InlineData("database-relative", "This controller profile requires one local PostgreSQL Unix socket directory.")]
    [InlineData("database-comma", "This controller profile requires one local PostgreSQL Unix socket directory.")]
    public async Task InvalidControllerTargetRefusesBeforeStateIpcAndDatabaseContact(string fault, string reason)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var fixture = new ControllerPreflightFixture(fault);
        var host = fixture.Start();
        await using var lifetime = host.ConfigureAwait(true);
        await host.WaitForExitAsync(guard.Token).ConfigureAwait(true);
        var logs = await host.ReadLogsAsync(guard.Token).ConfigureAwait(true);
        fixture.ObserveSettledChild();
        Assert.NotEqual(0, host.ExitCode);
        Assert.False(fixture.DatabaseContacted, "Invalid settings must not contact the owned database sentinel.");
        Assert.False(Directory.Exists(fixture.State), "Invalid settings must not create snapshot state.");
        Assert.False(Directory.Exists(fixture.Runtime), "Invalid settings must not acquire IPC directories or leases.");
        Assert.Contains(reason, logs, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvalidGrantCannotCreateStateOrReachTheUnopenedDatabase()
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var root = Path.Combine(Path.GetTempPath(), "m8-preflight-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var safeToDelete = true;
        try
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var keyPath = Path.Combine(root, "publication.pem");
            var database = Path.Combine(root, "database.txt");
            var configuration = Path.Combine(root, "control.json");
            var state = Path.Combine(root, "state");
            var zone = Guid.NewGuid();
            await File.WriteAllTextAsync(keyPath, key.ExportPkcs8PrivateKeyPem(), guard.Token).ConfigureAwait(true);
            await File.WriteAllTextAsync(database, "Host=" + Path.Combine(root, "unopened-database")
                + ";Port=5432;Database=fixture;Username=fixture;Pooling=false;Timeout=1;CommandTimeout=1", guard.Token).ConfigureAwait(true);
            var input = new
            {
                Epoch = Guid.NewGuid(),
                TargetNode = "fixture",
                KeyFile = keyPath,
                ConnectionStringFile = database,
                PublicationSocket = Path.Combine(root, "publication.sock"),
                Zones = new[] { new { ZoneId = zone, Origin = "example." } },
                Grants = new[] { new { TenantId = Guid.NewGuid(), ZoneId = zone, Origin = "example.", Actor = "fixture",
                    Expires = DateTimeOffset.UtcNow.AddMinutes(1), CredentialHash = new byte[] { 1 }, }, },
            };
            await File.WriteAllTextAsync(configuration, JsonSerializer.Serialize(input), guard.Token).ConfigureAwait(true);
            var host = new HostProcess("mk8.dns.Application", ["--socket", Path.Combine(root, "application.sock"), "--state", state,
                "--node", "fixture", "--role", "controller", "--control", configuration], 0);
            await using var lifetime = host.ConfigureAwait(true);
            safeToDelete = false;
            await host.WaitForExitAsync(guard.Token).ConfigureAwait(true);
            var logs = await host.ReadLogsAsync(guard.Token).ConfigureAwait(true);
            safeToDelete = true;
            Assert.NotEqual(0, host.ExitCode);
            Assert.Contains("Invalid scoped management grant", logs, StringComparison.Ordinal);
            Assert.False(Directory.Exists(state));
            Assert.False(File.Exists(Path.Combine(root, "application.sock")));
        }
        finally
        {
            if (safeToDelete) Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("--secrets-directory")]
    [InlineData("--secrets-file")]
    [InlineData("--recursive-config")]
    public async Task PublicExecutableRejectsLocatorsBeforeReadingAnyServiceValues(string locator)
    {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        // The intentionally invalid role data would produce a different failure
        // if the executable consulted its installation document before CLI refusal.
        var host = new HostProcess("mk8.dns.Gateway", [], 0, [locator, "nonsecret-fixture-locator"]);
        await using var lifetime = host.ConfigureAwait(true);
        await host.WaitForExitAsync(guard.Token).ConfigureAwait(true);
        Assert.NotEqual(0, host.ExitCode);
        var logs = await host.ReadLogsAsync(guard.Token).ConfigureAwait(true);
        Assert.Contains("ServiceArgumentsForbidden", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("nonsecret-fixture-locator", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("Required host argument", logs, StringComparison.Ordinal);
    }
}
