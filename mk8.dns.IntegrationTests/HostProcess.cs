using System.Diagnostics;
using System.Text.Json;

namespace Mk8.Dns.IntegrationTests;

internal sealed class HostProcess : IAsyncDisposable
{
    private readonly Process process;
    private readonly Task<string> output;
    private readonly Task<string> errors;
    private readonly string? diagnosticPrefix;
    private readonly DateTimeOffset startedAt = DateTimeOffset.UtcNow;
    private bool diagnosticsSaved;

    internal HostProcess(string host, string[] arguments, int injectedPort)
    {
        var diagnostics = Environment.GetEnvironmentVariable("MK8_DNS_TEST_HOST_LOGS");
        if (!string.IsNullOrEmpty(diagnostics))
        {
            if (!Path.IsPathFullyQualified(diagnostics) || !Directory.Exists(diagnostics))
                throw new ArgumentException("The test host diagnostic directory must already exist at an absolute path.", nameof(host));
            diagnosticPrefix = Path.Combine(diagnostics, host + "-" + Guid.NewGuid().ToString("N"));
        }
        var start = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = RepositoryPaths.Root,
        };
        start.ArgumentList.Add(RepositoryPaths.HostAssembly(host));
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        start.Environment["ASPNETCORE_URLS"] = FormattableString.Invariant($"http://0.0.0.0:{injectedPort}");
        start.Environment["Kestrel__Endpoints__Injected__Url"] = FormattableString.Invariant($"http://0.0.0.0:{injectedPort}");
        process = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the host process.");
        output = process.StandardOutput.ReadToEndAsync();
        errors = process.StandardError.ReadToEndAsync();
    }

    internal bool HasExited => process.HasExited;
    internal int ExitCode => process.ExitCode;

    internal async Task StopAsync(CancellationToken cancellationToken)
    {
        if (!process.HasExited)
        {
            var start = new ProcessStartInfo("/bin/kill") { UseShellExecute = false };
            start.ArgumentList.Add("-TERM");
            start.ArgumentList.Add(process.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            using var signal = Process.Start(start) ?? throw new InvalidOperationException("Cannot terminate the owned host.");
            await signal.WaitForExitAsync(cancellationToken).ConfigureAwait(true);
        }
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(true);
    }

    internal async Task KillAsync(CancellationToken cancellationToken)
    {
        if (!process.HasExited)
            process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(true);
        _ = await ReadLogsAsync(cancellationToken).ConfigureAwait(true);
        if (diagnosticPrefix is not null && !diagnosticsSaved)
        {
            await File.WriteAllTextAsync(diagnosticPrefix + ".stdout.log", await output.WaitAsync(cancellationToken).ConfigureAwait(true), cancellationToken).ConfigureAwait(true);
            await File.WriteAllTextAsync(diagnosticPrefix + ".stderr.log", await errors.WaitAsync(cancellationToken).ConfigureAwait(true), cancellationToken).ConfigureAwait(true);
            await File.WriteAllTextAsync(diagnosticPrefix + ".json", JsonSerializer.Serialize(new
            {
                Pid = process.Id,
                process.ExitCode,
                StartedUtc = startedAt,
                CompletedUtc = DateTimeOffset.UtcNow,
                Scope = "Owned integration-test child host; output captured at exit, no startup latency guarantee.",
            }), cancellationToken).ConfigureAwait(true);
            diagnosticsSaved = true;
        }
    }

    internal async Task<string> ReadLogsAsync(CancellationToken cancellationToken)
    {
        return await output.WaitAsync(cancellationToken).ConfigureAwait(true) + await errors.WaitAsync(cancellationToken).ConfigureAwait(true);
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await KillAsync(timeout.Token).ConfigureAwait(true);
        }
        finally
        {
            process.Dispose();
        }
    }
}
