using System.Diagnostics;

namespace Mk8.Dns.IntegrationTests;

internal sealed class HostProcess : IAsyncDisposable
{
    private readonly Process process;
    private readonly Task<string> output;
    private readonly Task<string> errors;

    internal HostProcess(string host, string[] arguments, int injectedPort)
    {
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

    internal async Task KillAsync(CancellationToken cancellationToken)
    {
        if (!process.HasExited)
            process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(true);
        _ = await ReadLogsAsync(cancellationToken).ConfigureAwait(true);
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
