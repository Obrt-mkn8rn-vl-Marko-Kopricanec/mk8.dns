using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class HostProcessRetirementTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task ActualExitAndReadersSettleDespiteCanceledObservers(bool cancelClose, bool cancelStop)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var root = Path.Combine(Path.GetTempPath(), "m8ret-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var canceled = new CancellationTokenSource();
        await canceled.CancelAsync().ConfigureAwait(true);
        Task? actualExit = null;
        Task? close = null;
        Exception? body = null;
        try
        {
            var cleanup = await Record.ExceptionAsync(async () =>
            {
                var path = Path.Combine(root, "management.sock");
                var host = new HostProcess("mk8.dns.Gateway", ["--socket", Path.Combine(root, "absent.sock"),
                    "--role", "management", "--management-socket", path], 0);
                await using var lifetime = host.ConfigureAwait(true);
                var (ownedExit, _, _) = host.Operations;
                actualExit = ownedExit;
                var installation = host.InstallationDirectory;
                body = await Record.ExceptionAsync(async () =>
                {
                    await BoundAsync(host, path, deadline.Token).ConfigureAwait(true);
                    Assert.True(Directory.Exists(installation));
                    Assert.False(ownedExit.IsCompleted);
                    if (cancelStop)
                    {
                        await CanceledStopAsync(host, canceled.Token, deadline.Token).ConfigureAwait(true);
                    }
                    else if (!cancelClose)
                    {
                        await host.StopAsync(deadline.Token).ConfigureAwait(true);
                        Assert.Equal(0, host.ExitCode);
                    }

                    close = cancelClose ? host.CloseAsync(canceled.Token) : host.DisposeAsync().AsTask();
                    await ObserveCloseAsync(close, cancelClose, canceled.Token, deadline.Token).ConfigureAwait(true);
                    await RetiredAsync(host, close, installation).ConfigureAwait(true);
                }).ConfigureAwait(true);
            }).ConfigureAwait(true);
            if (close?.IsCanceled is true && cleanup is OperationCanceledException failure && failure.CancellationToken == canceled.Token)
                cleanup = null;
            await TestTaskSettlement.AllAsync(
                () => body is null ? Task.CompletedTask : Task.FromException(body),
                () => cleanup is null ? Task.CompletedTask : Task.FromException(cleanup)).ConfigureAwait(true);
        }
        finally
        {
            // Keep dependent socket files if actual owned process exit was not established.
            if (actualExit?.IsCompletedSuccessfully is true) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task BoundAsync(HostProcess host, string path, CancellationToken token)
    {
        while (!File.Exists(path))
        {
            Assert.False(host.HasExited);
            await Task.Delay(20, token).ConfigureAwait(true);
        }
    }

    private static async Task ObserveCloseAsync(Task close, bool cancelClose, CancellationToken canceled, CancellationToken deadline)
    {
        if (cancelClose)
        {
            var failure = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => close.WaitAsync(deadline)).ConfigureAwait(true);
            Assert.Equal(canceled, failure.CancellationToken);
        }
        else
        {
            await close.WaitAsync(deadline).ConfigureAwait(true);
        }
    }

    private static async Task RetiredAsync(HostProcess host, Task close, string installation)
    {
        Assert.Same(close, host.DisposeAsync().AsTask());
        var (exit, output, errors) = host.Operations;
        Assert.True(exit.IsCompletedSuccessfully);
        Assert.True(output.IsCompletedSuccessfully);
        Assert.True(errors.IsCompletedSuccessfully);
        _ = await output.WaitAsync(CancellationToken.None).ConfigureAwait(true);
        _ = await errors.WaitAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.False(Directory.Exists(installation));
    }

    private static async Task CanceledStopAsync(HostProcess host, CancellationToken canceled, CancellationToken deadline)
    {
        var failure = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => host.StopAsync(canceled)).ConfigureAwait(true);
        Assert.Equal(canceled, failure.CancellationToken);
        Assert.NotNull(host.LastSignalExit);
        Assert.True(host.LastSignalExit.IsCompletedSuccessfully);
        await host.WaitForExitAsync(deadline).ConfigureAwait(true);
        Assert.Equal(0, host.ExitCode);
    }
}
