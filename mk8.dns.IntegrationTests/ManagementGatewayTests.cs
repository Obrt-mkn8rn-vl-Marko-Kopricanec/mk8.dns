using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Grpc.Core;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Transport;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class ManagementGatewayTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task HttpImportExportRequireFullZoneActionsAndPreserveHistoricalReplay()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8zonehttp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var control = new ControlFixture();
            var acme = RandomNumberGenerator.GetBytes(32);
            var configuration = await WriteConfigurationAsync(root, control, acme, await postgres.ResetDatabaseAsync().ConfigureAwait(true)).ConfigureAwait(true);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = timeout.Token;
            var controller = new HostProcess("mk8.dns.Application", configuration.ControllerArguments, Port());
            await using var controllerLifetime = controller.ConfigureAwait(true);
            var gateway = new HostProcess("mk8.dns.Gateway", ["--role", "management", "--socket", configuration.ControlSocket, "--management-socket", configuration.ApiSocket], Port());
            await using var gatewayLifetime = gateway.ConfigureAwait(true);
            await WaitReadyAsync(configuration.ControlSocket, controller, token).ConfigureAwait(true);
            using var http = new UnixManagementHttpClient(configuration.ApiSocket);
            await WaitHttpAsync(http, control.Edit() with { Action = "status" }, gateway, token).ConfigureAwait(true);
            await ExerciseZoneFilesAsync(http, control, acme, token).ConfigureAwait(true);
            foreach (var host in new[] { gateway, controller })
            {
                await host.StopAsync(token).ConfigureAwait(true);
                Assert.Equal(0, host.ExitCode);
                Assert.DoesNotContain("Unhandled exception", await host.ReadLogsAsync(token).ConfigureAwait(true), StringComparison.Ordinal);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task ExerciseZoneFilesAsync(UnixManagementHttpClient http, ControlFixture control, byte[] acme, CancellationToken token)
    {
        var import = control.Edit() with { Action = "import", Records = [], ZoneFile = ZoneFileManagementTests.Text };
        var accepted = await http.ExecuteAsync(import, token).ConfigureAwait(true);
        Assert.Equal(1L, accepted.Revision);
        var query = import with { Action = "export", OperationId = Guid.NewGuid(), ZoneFile = null };
        var initial = await http.ExecuteAsync(query, token).ConfigureAwait(true);
        Assert.Equal(accepted.ContentHash, initial.ContentHash);
        Assert.Equal("current", initial.State);
        Assert.Empty(initial.Records);
        Assert.Equal(accepted.ContentHash, ZoneBundleCodec.Compile(control.Zone, 1, ZoneMasterFileCodec.Import(DnsName.Parse("example."), initial.ZoneFile!)).ContentHash);
        foreach (var request in new[] { query, import with { ExpectedRevision = 1, OperationId = Guid.NewGuid() } })
        {
            var denied = await Assert.ThrowsAsync<HttpRequestException>(() => http.ExecuteAsync(request with { Credential = acme }, token).AsTask()).ConfigureAwait(true);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        }
        var invalid = import with { ExpectedRevision = 1, OperationId = Guid.NewGuid(), ZoneFile = ZoneFileManagementTests.Text + "$INCLUDE /etc/passwd\n" };
        var failed = await Assert.ThrowsAsync<HttpRequestException>(() => http.ExecuteAsync(invalid, token).AsTask()).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.BadRequest, failed.StatusCode);
        var changed = import with { ExpectedRevision = 1, OperationId = Guid.NewGuid(), ZoneFile = ZoneFileManagementTests.Text.Replace("192.0.2.42", "192.0.2.99", StringComparison.Ordinal) };
        Assert.Equal(2L, (await http.ExecuteAsync(changed, token).ConfigureAwait(true)).Revision);
        var replay = await http.ExecuteAsync(import with { ZoneFile = initial.ZoneFile }, token).ConfigureAwait(true);
        Assert.Equal(accepted.Revision, replay.Revision);
        Assert.Equal(accepted.ContentHash, replay.ContentHash);
        var current = await http.ExecuteAsync(query, token).ConfigureAwait(true);
        Assert.Equal(2L, current.Revision);
        Assert.NotEqual(initial.ContentHash, current.ContentHash, StringComparer.Ordinal);
        var conflict = await Assert.ThrowsAsync<HttpRequestException>(() => http.ExecuteAsync(import with { OperationId = Guid.NewGuid() }, token).AsTask()).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        var preserved = await http.ExecuteAsync(query, token).ConfigureAwait(true);
        Assert.Equal(current.Revision, preserved.Revision);
        Assert.Equal(current.ContentHash, preserved.ContentHash);
        Assert.Equal(current.ZoneFile, preserved.ZoneFile);
    }

    [Fact]
    public async Task HttpScopeReplayAndRevisionSurviveControllerRestartWithSameGateway()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8http-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var control = new ControlFixture();
            var acme = RandomNumberGenerator.GetBytes(32);
            var configuration = await WriteConfigurationAsync(root, control, acme, await postgres.ResetDatabaseAsync().ConfigureAwait(true)).ConfigureAwait(true);
            await RunScenarioAsync(configuration, control, acme).ConfigureAwait(true);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RunScenarioAsync(Configuration configuration, ControlFixture control, byte[] acme)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var token = timeout.Token;
        var controller = new HostProcess("mk8.dns.Application", configuration.ControllerArguments, Port());
        await using var controllerLifetime = controller.ConfigureAwait(true);
        var injected = Port();
        var gateway = new HostProcess("mk8.dns.Gateway", ["--role", "management", "--socket", configuration.ControlSocket, "--management-socket", configuration.ApiSocket], injected);
        await using var gatewayLifetime = gateway.ConfigureAwait(true);
        await WaitReadyAsync(configuration.ControlSocket, controller, token).ConfigureAwait(true);
        using var http = new UnixManagementHttpClient(configuration.ApiSocket);
        await WaitHttpAsync(http, control.Edit() with { Action = "status" }, gateway, token).ConfigureAwait(true);
        using (var denied = new TcpClient())
            await Assert.ThrowsAsync<SocketException>(() => denied.ConnectAsync(IPAddress.Loopback, injected, token).AsTask()).ConfigureAwait(true);
        var read = await ExerciseScopesAsync(http, control, acme, token).ConfigureAwait(true);
        await controller.StopAsync(token).ConfigureAwait(true);
        Assert.Equal(0, controller.ExitCode);
        var absent = await Assert.ThrowsAsync<HttpRequestException>(() => http.ExecuteAsync(read, token).AsTask()).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, absent.StatusCode);
        var restarted = new HostProcess("mk8.dns.Application", configuration.ControllerArguments, Port());
        await using var restartedLifetime = restarted.ConfigureAwait(true);
        await WaitReadyAsync(configuration.ControlSocket, restarted, token).ConfigureAwait(true);
        Assert.Equal(3L, (await http.ExecuteAsync(read, token).ConfigureAwait(true)).Revision);
        Assert.False(gateway.HasExited);
        await gateway.StopAsync(token).ConfigureAwait(true);
        Assert.Equal(0, gateway.ExitCode);
        // The same HTTP client must also reconnect when the frontend's socket is replaced.
        var successor = new HostProcess("mk8.dns.Gateway", ["--role", "management", "--socket", configuration.ControlSocket, "--management-socket", configuration.ApiSocket], Port());
        await using var successorLifetime = successor.ConfigureAwait(true);
        await WaitHttpAsync(http, control.Edit() with { Action = "status" }, successor, token).ConfigureAwait(true);
        Assert.Equal(3L, (await http.ExecuteAsync(read, token).ConfigureAwait(true)).Revision);
        foreach (var process in new[] { gateway, successor, restarted })
        {
            await process.StopAsync(token).ConfigureAwait(true);
            Assert.Equal(0, process.ExitCode);
            Assert.DoesNotContain("Unhandled exception", await process.ReadLogsAsync(token).ConfigureAwait(true), StringComparison.Ordinal);
        }
    }

    private static async Task<ManagementRequest> ExerciseScopesAsync(UnixManagementHttpClient http, ControlFixture control, byte[] acme, CancellationToken token)
    {
        var edit = control.Edit();
        Assert.Equal(1L, (await http.ExecuteAsync(edit, token).ConfigureAwait(true)).Revision);
        var status = await http.ExecuteAsync(edit with { Action = "status" }, token).ConfigureAwait(true);
        Assert.Equal(edit.OperationId, status.OperationId);
        var present = new ManagementRequest("patch", control.Tenant, control.Zone, Guid.NewGuid(), 1, edit.Origin, Array.Empty<ZoneRecordData>(), acme)
        { Changes = [RecordManagementFixture.Change("_acme-challenge.example.", 16, [RecordManagementFixture.Text('A')])] };
        var accepted = await http.ExecuteAsync(present, token).ConfigureAwait(true);
        Assert.Equal(2L, accepted.Revision);
        var read = present with { Action = "read", OperationId = Guid.NewGuid(), Changes = [], Selection = [new(RecordManagementFixture.ChallengeName.ToWire(), 16)] };
        Assert.Single((await http.ExecuteAsync(read, token).ConfigureAwait(true)).Records);
        var actorDenial = await Assert.ThrowsAsync<HttpRequestException>(() => http.ExecuteAsync(edit with { Action = "status", Credential = acme }, token).AsTask()).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, actorDenial.StatusCode);
        var scopeDenial = await Assert.ThrowsAsync<HttpRequestException>(() => http.ExecuteAsync(read with { Selection = [new(DnsName.Parse("www.example.").ToWire(), 1)] }, token).AsTask()).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Forbidden, scopeDenial.StatusCode);
        var conflict = await Assert.ThrowsAsync<HttpRequestException>(() => http.ExecuteAsync(present with { OperationId = Guid.NewGuid() }, token).AsTask()).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        var cleanup = present with { ExpectedRevision = 2, OperationId = Guid.NewGuid(), Changes = [RecordManagementFixture.Change("_acme-challenge.example.", 16, [], [RecordManagementFixture.Text('A')])] };
        Assert.Equal(3L, (await http.ExecuteAsync(cleanup, token).ConfigureAwait(true)).Revision);
        var replay = await http.ExecuteAsync(present, token).ConfigureAwait(true);
        Assert.Equal(accepted.Revision, replay.Revision);
        Assert.Equal(accepted.ContentHash, replay.ContentHash);
        var current = await http.ExecuteAsync(read, token).ConfigureAwait(true);
        Assert.Equal(3L, current.Revision);
        Assert.Empty(current.Records);
        return read;
    }

    private static async Task<Configuration> WriteConfigurationAsync(string root, ControlFixture control, byte[] acme, string connection)
    {
        var controller = Path.Combine(root, "control", "app.sock");
        var api = Path.Combine(root, "http", "api.sock");
        var keyFile = Path.Combine(root, "signing.pem");
        var database = Path.Combine(root, "database.txt");
        var file = Path.Combine(root, "controller.json");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await PrivateAsync(keyFile, Encoding.UTF8.GetBytes(key.ExportPkcs8PrivateKeyPem())).ConfigureAwait(true);
        await PrivateAsync(database, Encoding.UTF8.GetBytes(connection)).ConfigureAwait(true);
        object[] grants = [
            new { TenantId = control.Tenant, ZoneId = control.Zone, Origin = "example.", Actor = "http-operator", Expires = DateTimeOffset.UtcNow.AddHours(1), CredentialHash = SHA256.HashData(control.Credential), Actions = new[] { "edit", "patch", "read", "status", "import", "export" } },
            new { TenantId = control.Tenant, ZoneId = control.Zone, Origin = "example.", Actor = "http-acme", Expires = DateTimeOffset.UtcNow.AddHours(1), CredentialHash = SHA256.HashData(acme), Profile = "acme", Actions = new[] { "patch", "read", "status" }, RecordScopes = new[] { new { Owner = "_acme-challenge.example.", Type = 16 } } },
        ];
        await PrivateAsync(file, JsonSerializer.SerializeToUtf8Bytes(new
        {
            control.Epoch,
            TargetNode = ControlFixture.Node,
            Zones = new[] { new { ZoneId = control.Zone, Origin = "example." } },
            KeyFile = keyFile,
            ConnectionStringFile = database,
            PublicationSocket = Path.Combine(root, "offline", "app.sock"),
            Grants = grants,
        })).ConfigureAwait(true);
        return new Configuration(controller, api, ["--socket", controller, "--state", Path.Combine(root, "controller-state"), "--node", "http-controller", "--role", "controller", "--control", file]);
    }

    private static async Task PrivateAsync(string path, byte[] content)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        await File.WriteAllBytesAsync(path, content).ConfigureAwait(true);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static async Task WaitReadyAsync(string path, HostProcess process, CancellationToken token)
    {
        using var client = new UnixApplicationClient(path);
        while (true)
        {
            if (process.HasExited)
                Assert.Fail(await process.ReadLogsAsync(token).ConfigureAwait(true));
            try
            {
                Assert.Equal("controller", (await client.GetStatusAsync(ProtocolVersion.Current, token).ConfigureAwait(true)).Role);
                return;
            }
            catch (RpcException) { }
            await Task.Delay(20, token).ConfigureAwait(true);
        }
    }

    private static async Task WaitHttpAsync(UnixManagementHttpClient http, ManagementRequest request, HostProcess process, CancellationToken token)
    {
        while (true)
        {
            if (process.HasExited)
                Assert.Fail(await process.ReadLogsAsync(token).ConfigureAwait(true));
            try
            {
                _ = await http.ExecuteAsync(request, token).ConfigureAwait(true);
                Assert.Fail("A nonexistent receipt cannot succeed.");
            }
            catch (HttpRequestException exception) when (exception.StatusCode == HttpStatusCode.NotFound) { return; }
            catch (HttpRequestException) { }
            await Task.Delay(20, token).ConfigureAwait(true);
        }
    }

    private static int Port()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private sealed record Configuration(string ControlSocket, string ApiSocket, string[] ControllerArguments);
}
