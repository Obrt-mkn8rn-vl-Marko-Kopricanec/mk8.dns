using System.Net.Sockets;
using Mk8.Dns.Application.DAL;
using Npgsql;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class PostgresSnapshotPolicyTests
{
    private const string Identity = "Host=/unused-fixture-socket;Port=5432;Username=fixture;Database=fixture";

    [Fact]
    public void CompletedProfileSurvivesTheActualDriverRoundTrip()
    {
        var settings = new NpgsqlConnectionStringBuilder(LocalPostgresConnection.Create(Identity).ConnectionString);
        Assert.Equal("None", settings.RequireAuth);
        Assert.Equal("UTF8", settings.ClientEncoding);
        Assert.Equal("UTC", settings.Timezone);
        Assert.Equal("mk8.dns", settings.ApplicationName);
        Assert.Equal(" ", settings.Options);
        Assert.Equal("any", settings.TargetSessionAttributes);
        Assert.Equal(SslMode.Disable, settings.SslMode);
        Assert.Equal(GssEncryptionMode.Disable, settings.GssEncryptionMode);
        Assert.Equal(SslNegotiation.Postgres, settings.SslNegotiation);
        var supplied = new NpgsqlConnectionStringBuilder(Identity)
        {
            Password = "snapshot-fixture-password",
            ApplicationName = "snapshot-fixture-app",
            Options = "-c search_path=public",
            Timezone = "Europe/Zagreb",
            RequireAuth = "ScramSHA256",
        };
        var retained = new NpgsqlConnectionStringBuilder(LocalPostgresConnection.Create(supplied.ConnectionString).ConnectionString);
        Assert.Equal(supplied.Password, retained.Password);
        Assert.Equal(supplied.ApplicationName, retained.ApplicationName);
        Assert.Equal(supplied.Options, retained.Options);
        Assert.Equal(supplied.Timezone, retained.Timezone);
        Assert.Equal(supplied.RequireAuth, retained.RequireAuth);
    }

    [Theory]
    [InlineData("Passfile", "/sentinel-protected-input", "SecretDatabaseExternalInputRefused")]
    [InlineData("SSL Key", "/sentinel-protected-input", "SecretDatabaseExternalInputRefused")]
    [InlineData("Require Auth", "GSS", "SecretDatabaseAuthenticationRefused")]
    [InlineData("SSL Mode", "Require", "SecretDatabaseLocalTransportRequired")]
    [InlineData("Username", "", "SecretDatabaseScopeMissing")]
    public void ExternalOrIncompleteInputsRefuseBeforeAcquisition(string key, string value, string code)
    {
        var settings = new NpgsqlConnectionStringBuilder(Identity) { [key] = value };
        var failure = Assert.Throws<ArgumentException>(() => PostgresControlPlaneStore.ValidateLocalConnectionString(settings.ConnectionString));
        Assert.StartsWith(code, failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("sentinel-protected-input", failure.ToString(), StringComparison.Ordinal);
        Assert.Null(failure.InnerException);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualLocalHandshakeUsesOnlySnapshotInputs(bool supplyPassword)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        var root = Path.Combine(Path.GetTempPath(), "m8snap-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            listener.Bind(new UnixDomainSocketEndPoint(Path.Combine(root, ".s.PGSQL.5432")));
            listener.Listen(1);
            var settings = new NpgsqlConnectionStringBuilder(Identity)
            {
                Host = root,
                Pooling = false,
                Timeout = 5,
                CommandTimeout = 10,
                Password = supplyPassword ? "snapshot-fixture-password" : null,
            };
            await RunStoreAsync(listener, settings, deadline).ConfigureAwait(true);
        }
        finally
        {
            listener.Dispose();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RunStoreAsync(Socket listener, NpgsqlConnectionStringBuilder settings, CancellationTokenSource deadline)
    {
        Exception? body = null;
        var cleanup = await Record.ExceptionAsync(async () =>
        {
            var store = new PostgresControlPlaneStore(settings.ConnectionString);
            await using var lifetime = store.ConfigureAwait(true);
            var peer = PostgresSnapshotPeer.ChallengeAsync(listener, settings.Password, deadline.Token);
            var opening = store.InitializeAsync(Guid.NewGuid(), deadline.Token).AsTask();
            body = await Record.ExceptionAsync(() => TestTaskSettlement.RunAsync(async () =>
            {
                _ = await Assert.ThrowsAnyAsync<NpgsqlException>(() => opening.WaitAsync(deadline.Token)).ConfigureAwait(true);
                await peer.WaitAsync(deadline.Token).ConfigureAwait(true);
            }, () => TestTaskSettlement.AllAsync(
                () => deadline.CancelAsync(),
                () => TestTaskSettlement.ObserveAsync(opening.WaitAsync(CancellationToken.None), error => error is NpgsqlException || IsOwnCancellation(error, deadline.Token)),
                () => TestTaskSettlement.ObserveAsync(peer.WaitAsync(CancellationToken.None), error => IsOwnCancellation(error, deadline.Token))))).ConfigureAwait(true);
        }).ConfigureAwait(true);
        await TestTaskSettlement.AllAsync(
            () => body is null ? Task.CompletedTask : Task.FromException(body),
            () => cleanup is null ? Task.CompletedTask : Task.FromException(cleanup)).ConfigureAwait(true);
    }

    private static bool IsOwnCancellation(Exception error, CancellationToken token)
        => token.IsCancellationRequested && error is OperationCanceledException canceled && canceled.CancellationToken == token;
}
