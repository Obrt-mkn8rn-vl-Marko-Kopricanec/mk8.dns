using System.Diagnostics;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class PostgresCommandOwnershipTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task NormalAndTimedOutCommandsSettleActualExitAndBothReaders(bool timeout, bool observerFailure)
    {
        var start = new ProcessStartInfo("/bin/sh") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(timeout ? "printf owned-output; printf owned-error >&2; exec sleep 60" : "printf owned-output; printf owned-error >&2");
        Task? exit = null;
        Task<string>? output = null;
        Task<string>? errors = null;
        var run = PostgresCommand.RunAsync(start, TimeSpan.FromSeconds(1), (ownedExit, ownedOutput, ownedErrors) =>
        {
            exit = ownedExit;
            output = ownedOutput;
            errors = ownedErrors;
        });
        var observer = new IOException("Controlled process observer failure.");
        var observed = await Record.ExceptionAsync(() => TestTaskSettlement.RunAsync(async () =>
        {
            if (observerFailure) throw observer;
            if (timeout) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(10), TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            else await run.WaitAsync(TimeSpan.FromSeconds(10), TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.NotNull(exit); Assert.NotNull(output); Assert.NotNull(errors);
            Assert.True(exit.IsCompletedSuccessfully);
            Assert.True(output.IsCompletedSuccessfully);
            Assert.True(errors.IsCompletedSuccessfully);
            Assert.Equal("owned-output", await output.WaitAsync(CancellationToken.None).ConfigureAwait(true));
            Assert.Equal("owned-error", await errors.WaitAsync(CancellationToken.None).ConfigureAwait(true));
        }, async () =>
        {
            var terminal = await Record.ExceptionAsync(() => run.WaitAsync(CancellationToken.None)).ConfigureAwait(true);
            if (timeout) Assert.IsType<OperationCanceledException>(terminal, exactMatch: false);
            else Assert.Null(terminal);
        })).ConfigureAwait(true);
        if (observerFailure) Assert.Same(observer, observed);
        else Assert.Null(observed);
    }
}
