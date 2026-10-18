using System.Diagnostics;
using System.Text.Json;

namespace Mk8.Dns.IntegrationTests;

internal sealed partial class HostProcess : IAsyncDisposable
{
    private readonly Process process;
    private readonly HostInstallationFixture installation;
    private readonly Task<string> output;
    private readonly Task<string> errors;
    private readonly Task exit;
    private readonly string? diagnosticPrefix;
    private readonly DateTimeOffset startedAt = DateTimeOffset.UtcNow;
    private bool diagnosticsSaved;

    internal HostProcess(string host, string[] arguments, int injectedPort, string[]? forbiddenArguments = null, string? dnsPolicy = null)
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
        installation = new HostInstallationFixture(host, arguments, dnsPolicy);
        start.ArgumentList.Add(installation.AssemblyPath);
        if (forbiddenArguments is not null)
            foreach (var argument in forbiddenArguments) start.ArgumentList.Add(argument);
        start.Environment["ASPNETCORE_URLS"] = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"http://0.0.0.0:{injectedPort}");
        start.Environment["Kestrel__Endpoints__Injected__Url"] = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"http://0.0.0.0:{injectedPort}");
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
        start.Environment["DOTNET_ENVIRONMENT"] = "Development";
        start.Environment["ASPNETCORE_HOSTINGSTARTUPASSEMBLIES"] = "DeliberatelyAbsentOwnedFixtureAssembly";
        start.Environment[host["mk8.dns.".Length..] + "__Settings"] = "not-a-service-configuration";
        try { process = Process.Start(start) ?? throw new InvalidOperationException("Cannot start the host process."); }
        catch { installation.Dispose(); throw; }
        output = process.StandardOutput.ReadToEndAsync();
        errors = process.StandardError.ReadToEndAsync();
        exit = process.WaitForExitAsync(CancellationToken.None);
    }

    internal bool HasExited => process.HasExited;
    internal int ExitCode => process.ExitCode;
    internal Task? LastSignalExit { get; private set; }

    internal Task WaitForExitAsync(CancellationToken cancellationToken)
        => exit.WaitAsync(cancellationToken);

    internal async Task StopAsync(CancellationToken cancellationToken)
    {
        if (!process.HasExited)
        {
            var start = new ProcessStartInfo("/bin/kill") { UseShellExecute = false };
            start.ArgumentList.Add("-TERM");
            start.ArgumentList.Add(process.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            using var signal = Process.Start(start) ?? throw new InvalidOperationException("Cannot terminate the owned host.");
            var signaled = signal.WaitForExitAsync(CancellationToken.None);
            LastSignalExit = signaled;
            await TestTaskSettlement.WaitAsync(signaled, cancellationToken).ConfigureAwait(true);
        }
        await exit.WaitAsync(cancellationToken).ConfigureAwait(true);
    }

    internal async Task KillAsync(CancellationToken cancellationToken)
    {
        RequestKill();
        await exit.WaitAsync(cancellationToken).ConfigureAwait(true);
        _ = await ReadLogsAsync(cancellationToken).ConfigureAwait(true);
        await SaveDiagnosticsAsync(cancellationToken).ConfigureAwait(true);
    }

    private async Task SaveDiagnosticsAsync(CancellationToken cancellationToken)
    {
        if (diagnosticPrefix is not null && !diagnosticsSaved)
        {
            await File.WriteAllTextAsync(diagnosticPrefix + ".stdout.log", await output.WaitAsync(cancellationToken).ConfigureAwait(true), cancellationToken).ConfigureAwait(true);
            await File.WriteAllTextAsync(diagnosticPrefix + ".stderr.log", await errors.WaitAsync(cancellationToken).ConfigureAwait(true), cancellationToken).ConfigureAwait(true);
            await File.WriteAllTextAsync(diagnosticPrefix + ".json", JsonSerializer.Serialize(new
            {
                Pid = process.Id,
                process.ExitCode,
                StartedUtc = startedAt,
                InstallationAssemblyHashes = installation.AssemblyHashes,
                BootstrapScope = "Task-owned fixed installation document; no active document/key values retained. DLL hashes are copy-before-start POINTS, not loaded identity.",
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

}
