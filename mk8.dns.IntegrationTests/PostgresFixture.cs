using System.Diagnostics;
using Npgsql;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

internal sealed class PostgresFixture : IAsyncLifetime
{
    private const string Bin = "/usr/lib/postgresql/17/bin/";
    private string? root;
    private bool started;

    public async Task InitializeAsync()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists(Bin + "initdb"))
            throw new PlatformNotSupportedException("The PostgreSQL integration profile requires the existing PostgreSQL 17 development binaries.");
        root = Path.Combine(Path.GetTempPath(), "m8pg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            await RunAsync("initdb", ["-D", Path.Combine(root, "data"), "--no-locale", "--encoding=UTF8", "--data-checksums", "--auth-local=trust", "--auth-host=reject"]).ConfigureAwait(true);
            await File.AppendAllTextAsync(Path.Combine(root, "data", "postgresql.conf"), FormattableString.Invariant($"\nlisten_addresses = ''\nunix_socket_directories = '{root}'\nunix_socket_permissions = 0700\nfsync = on\nfull_page_writes = on\nsynchronous_commit = on\n")).ConfigureAwait(true);
            await RunAsync("pg_ctl", ["-D", Path.Combine(root, "data"), "-l", Path.Combine(root, "postgres.log"), "-w", "-t", "15", "start"]).ConfigureAwait(true);
            started = true;
        }
        catch
        {
            await DisposeAsync().ConfigureAwait(true);
            throw;
        }
    }

    internal async Task<string> ResetDatabaseAsync()
    {
        var builder = new NpgsqlConnectionStringBuilder { Host = root!, Port = 5432, Username = Environment.UserName, Database = "postgres", Timeout = 5, CommandTimeout = 10, Pooling = false };
        var connection = new NpgsqlConnection(builder.ConnectionString);
        await using (connection.ConfigureAwait(true))
        {
            await connection.OpenAsync().ConfigureAwait(true);
            using var command = new NpgsqlCommand("DROP SCHEMA public CASCADE; CREATE SCHEMA public", connection);
            _ = await command.ExecuteNonQueryAsync().ConfigureAwait(true);
        }
        return builder.ConnectionString;
    }

    public async Task DisposeAsync()
    {
        if (root is null)
            return;
        if (started || File.Exists(Path.Combine(root, "data", "postmaster.pid")))
        {
            await RunAsync("pg_ctl", ["-D", Path.Combine(root, "data"), "-w", "-t", "15", "-m", "fast", "stop"]).ConfigureAwait(true);
            started = false;
        }
        Directory.Delete(root, recursive: true);
        root = null;
    }

    private static async Task RunAsync(string executable, string[] arguments)
    {
        var start = new ProcessStartInfo(Bin + executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the owned PostgreSQL development process.");
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(true);
            if (process.ExitCode != 0)
                throw new InvalidOperationException(await output.ConfigureAwait(true) + await errors.ConfigureAwait(true));
        }
        catch
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
            throw;
        }
    }
}
