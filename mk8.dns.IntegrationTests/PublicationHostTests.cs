using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Grpc.Core;
using Mk8.Dns.Contracts;
using Mk8.Dns.Transport;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class PublicationHostTests : IAsyncLifetime
{
    private readonly PostgresFixture postgres = new();
    public Task InitializeAsync() => postgres.InitializeAsync();
    public Task DisposeAsync() => postgres.DisposeAsync();
    [Fact]
    public async Task OperatorEditsReachLiveGatewayAndSurviveControllerAndReplicaRestarts()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8hosts-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var control = new ControlFixture();
            var connection = await postgres.ResetDatabaseAsync().ConfigureAwait(true);
            var configuration = await WriteConfigurationAsync(root, control, connection).ConfigureAwait(true);
            await RunHostsAsync(configuration, control).ConfigureAwait(true);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RunHostsAsync(HostConfiguration configuration, ControlFixture control)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var token = timeout.Token;
        var replica = new HostProcess("mk8.dns.Application", configuration.ReplicaArguments, Port());
        await using var replicaLifetime = replica.ConfigureAwait(true);
        var gateway = new HostProcess("mk8.dns.Gateway", ["--socket", configuration.QuerySocket, "--health-port", Port().ToString(CultureInfo.InvariantCulture), "--dns-address", "127.0.0.2", "--dns-port", configuration.DnsPort.ToString(CultureInfo.InvariantCulture)], Port());
        await using var gatewayLifetime = gateway.ConfigureAwait(true);
        var controller = new HostProcess("mk8.dns.Application", configuration.ControllerArguments, Port());
        await using var controllerLifetime = controller.ConfigureAwait(true);
        await WaitStatusAsync(configuration.ControlSocket, "controller", controller, token).ConfigureAwait(true);
        await WaitStatusAsync(configuration.QuerySocket, "authoritative-replica", replica, token).ConfigureAwait(true);
        var first = control.Edit();
        var accepted = await EditWithOperatorAsync(configuration, first, token).ConfigureAwait(true);
        Assert.Equal(1L, accepted.Revision);
        Assert.Equal(1u, accepted.Serial);
        await WaitAnswerAsync(configuration.DnsPort, 42, token).ConfigureAwait(true);
        using var client = new UnixControlClient(configuration.ControlSocket);
        var second = control.Edit(1, 43);
        Assert.Equal(2L, (await client.ExecuteAsync(second, token).ConfigureAwait(true)).Revision);
        await WaitActivatedAsync(client, second, token).ConfigureAwait(true);
        await WaitAnswerAsync(configuration.DnsPort, 43, token).ConfigureAwait(true);
        await controller.StopAsync(token).ConfigureAwait(true);
        Assert.Equal(0, controller.ExitCode);
        await WaitAnswerAsync(configuration.DnsPort, 43, token).ConfigureAwait(true);
        await CheckRestartsAsync(configuration, control, client, gateway, replica, token).ConfigureAwait(true);
    }

    private static async Task CheckRestartsAsync(HostConfiguration configuration, ControlFixture control, UnixControlClient client, HostProcess gateway, HostProcess replica, CancellationToken token)
    {
        var restartedController = new HostProcess("mk8.dns.Application", configuration.ControllerArguments, Port());
        await using var restartedControllerLifetime = restartedController.ConfigureAwait(true);
        await WaitStatusAsync(configuration.ControlSocket, "controller", restartedController, token).ConfigureAwait(true);
        await replica.StopAsync(token).ConfigureAwait(true);
        Assert.Equal(0, replica.ExitCode);
        var third = control.Edit(2, 44);
        var pending = await client.ExecuteAsync(third, token).ConfigureAwait(true);
        Assert.Equal("accepted", pending.State);
        Assert.Equal(3L, pending.Revision);
        var restartedReplica = new HostProcess("mk8.dns.Application", configuration.ReplicaArguments, Port());
        await using var restartedReplicaLifetime = restartedReplica.ConfigureAwait(true);
        await WaitStatusAsync(configuration.QuerySocket, "authoritative-replica", restartedReplica, token).ConfigureAwait(true);
        await WaitActivatedAsync(client, third, token).ConfigureAwait(true);
        await WaitAnswerAsync(configuration.DnsPort, 44, token).ConfigureAwait(true);
        await AssertShutdownAsync(gateway, restartedReplica, restartedController, token).ConfigureAwait(true);
    }

    private static async Task<HostConfiguration> WriteConfigurationAsync(string root, ControlFixture control, string connection)
    {
        var query = Path.Combine(root, "query", "app.sock");
        var publication = Path.Combine(root, "publication", "app.sock");
        var management = Path.Combine(root, "management", "app.sock");
        var database = Path.Combine(root, "database.txt");
        var signing = Path.Combine(root, "signing.pem");
        var verifying = Path.Combine(root, "verifying.pem");
        var credential = Path.Combine(root, "credential.bin");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await WritePrivateAsync(database, System.Text.Encoding.UTF8.GetBytes(connection)).ConfigureAwait(true);
        await WritePrivateAsync(signing, System.Text.Encoding.UTF8.GetBytes(key.ExportPkcs8PrivateKeyPem())).ConfigureAwait(true);
        await WritePrivateAsync(verifying, System.Text.Encoding.UTF8.GetBytes(key.ExportSubjectPublicKeyInfoPem())).ConfigureAwait(true);
        await WritePrivateAsync(credential, control.Credential).ConfigureAwait(true);
        var zones = new[] { new { ZoneId = control.Zone, Origin = "example." } };
        var replicaFile = Path.Combine(root, "replica.json");
        await WritePrivateAsync(replicaFile, JsonSerializer.SerializeToUtf8Bytes(new { control.Epoch, TargetNode = ControlFixture.Node, Zones = zones, KeyFile = verifying })).ConfigureAwait(true);
        var controllerFile = Path.Combine(root, "controller.json");
        await WritePrivateAsync(controllerFile, JsonSerializer.SerializeToUtf8Bytes(new
        {
            control.Epoch,
            TargetNode = ControlFixture.Node,
            Zones = zones,
            KeyFile = signing,
            ConnectionStringFile = database,
            PublicationSocket = publication,
            Grants = new[] { new { TenantId = control.Tenant, ZoneId = control.Zone, Origin = "example.", Actor = "process-operator", Expires = DateTimeOffset.UtcNow.AddHours(1), CredentialHash = SHA256.HashData(control.Credential) } },
        })).ConfigureAwait(true);
        return new HostConfiguration(root, query, management, credential, Port(),
            ["--socket", query, "--state", Path.Combine(root, "replica-state"), "--node", ControlFixture.Node, "--role", "authoritative-replica", "--control", replicaFile, "--publication-socket", publication],
            ["--socket", management, "--state", Path.Combine(root, "controller-state"), "--node", "process-controller", "--role", "controller", "--control", controllerFile]);
    }

    private static async Task<ManagementReply> EditWithOperatorAsync(HostConfiguration configuration, ManagementRequest request, CancellationToken token)
    {
        var path = Path.Combine(configuration.Root, "request.json");
        // Exercise an existing full-edit request file without the new optional RRset fields.
        await WritePrivateAsync(path, JsonSerializer.SerializeToUtf8Bytes(new { request.Action, request.TenantId, request.ZoneId, request.OperationId, request.ExpectedRevision, request.Origin, request.Records, Credential = ReadOnlyMemory<byte>.Empty })).ConfigureAwait(true);
        var process = new HostProcess("mk8.dns.Operator", ["--socket", configuration.ControlSocket, "--request", path, "--credential", configuration.CredentialFile], Port());
        await using var lifetime = process.ConfigureAwait(true);
        while (!process.HasExited)
            await Task.Delay(20, token).ConfigureAwait(true);
        var logs = await process.ReadLogsAsync(token).ConfigureAwait(true);
        Assert.True(process.ExitCode == 0, logs);
        return JsonSerializer.Deserialize<ManagementReply>(logs.Trim()) ?? throw new InvalidDataException("Operator returned no receipt.");
    }

    private static async Task WritePrivateAsync(string path, byte[] bytes)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException();
        await File.WriteAllBytesAsync(path, bytes).ConfigureAwait(true);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static async Task WaitStatusAsync(string path, string role, HostProcess process, CancellationToken token)
    {
        using var client = new UnixApplicationClient(path);
        while (true)
        {
            if (process.HasExited)
                Assert.Fail(await process.ReadLogsAsync(token).ConfigureAwait(true));
            try
            {
                Assert.Equal(role, (await client.GetStatusAsync(ProtocolVersion.Current, token).ConfigureAwait(true)).Role);
                return;
            }
            catch (RpcException) { }
            await Task.Delay(50, token).ConfigureAwait(true);
        }
    }

    private static async Task WaitActivatedAsync(UnixControlClient client, ManagementRequest request, CancellationToken token)
    {
        while (true)
        {
            var status = await client.ExecuteAsync(request with { Action = "status" }, token).ConfigureAwait(true);
            if (string.Equals(status.State, "activated", StringComparison.Ordinal))
                return;
            await Task.Delay(50, token).ConfigureAwait(true);
        }
    }

    private static async Task WaitAnswerAsync(int port, byte address, CancellationToken token)
    {
        var endpoint = new IPEndPoint(IPAddress.Parse("127.0.0.2"), port);
        byte[] query = [0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 0, 0, 1, 0, 1];
        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        while (true)
        {
            _ = await udp.SendToAsync(query, endpoint, token).ConfigureAwait(true);
            var buffer = new byte[512];
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(token);
            attempt.CancelAfter(TimeSpan.FromMilliseconds(500));
            try
            {
                var received = await udp.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), attempt.Token).ConfigureAwait(true);
                Assert.Equal(endpoint, received.RemoteEndPoint);
                if ((buffer[3] & 15) == 0 && received.ReceivedBytes > 32 && buffer.AsSpan(received.ReceivedBytes - 4, 4).SequenceEqual(new byte[] { 192, 0, 2, address }))
                    return;
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
            await Task.Delay(50, token).ConfigureAwait(true);
        }
    }

    private static async Task AssertShutdownAsync(HostProcess gateway, HostProcess replica, HostProcess controller, CancellationToken token)
    {
        foreach (var process in new[] { gateway, replica, controller })
        {
            await process.StopAsync(token).ConfigureAwait(true);
            Assert.Equal(0, process.ExitCode);
            var logs = await process.ReadLogsAsync(token).ConfigureAwait(true);
            Assert.DoesNotContain("Unhandled exception", logs, StringComparison.Ordinal);
            Assert.DoesNotContain("\"LogLevel\":\"Error\"", logs, StringComparison.Ordinal);
        }
    }

    private static int Port()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private sealed record HostConfiguration(string Root, string QuerySocket, string ControlSocket, string CredentialFile, int DnsPort, string[] ReplicaArguments, string[] ControllerArguments);
}
