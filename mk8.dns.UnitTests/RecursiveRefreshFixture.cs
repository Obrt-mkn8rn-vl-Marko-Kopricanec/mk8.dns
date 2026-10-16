using System.Net;
using Mk8.Dns.Application;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class RecursiveRefreshFixture : IAsyncDisposable
{
    private readonly NativeClientHostFixture source = new();
    private Task? execution;
    internal ClientProofEpochFixture Inputs => source.Inputs;
    internal Exception? ExpectedRunFailure { get; set; }
    internal CancellationToken? ExpectedCancellation { get; set; }

    internal Task<DnssecClientHost> CreateAsync(bool ipv6 = false, IPEndPoint? endpoint = null)
        => source.CreateAsync(ipv6, endpoint);

    internal Task RunAsync(DnssecClientHost host, DnssecAnchorRefresher refresher,
        DnssecAnchorPollingPolicy policy, TimeProvider clock, CancellationToken token)
    {
        if (execution is not null) throw new InvalidOperationException("Controlled execution already started.");
        execution = RecursiveRefreshExecution.RunAsync(host, refresher, policy, clock, token);
        return execution;
    }

    public async ValueTask DisposeAsync()
    {
        var closing = source.Host is null ? Task.CompletedTask : source.Host.DisposeAsync().AsTask();
        List<Exception> failures = [];
        await TestTaskSettlement.CaptureAsync(TestTaskSettlement.AllAsync(
            () => TestTaskSettlement.WaitAsync(closing.WaitAsync(CancellationToken.None), AnchorRefreshFixture.Timeout, IsExpected),
            () => execution is null ? Task.CompletedTask : TestTaskSettlement.WaitAsync(execution.WaitAsync(CancellationToken.None),
                AnchorRefreshFixture.Timeout, IsExpected)), failures).ConfigureAwait(true);
        await TestTaskSettlement.CaptureAsync(CloseSourceAsync(), failures).ConfigureAwait(true);
        TestTaskSettlement.ThrowFailures(failures);
    }

    private async Task CloseSourceAsync() => await source.DisposeAsync().ConfigureAwait(true);

    private bool IsExpected(Exception error)
    {
        if (ExpectedRunFailure is not null && NativeClientListenerFixture.OnlyExpected(error, ExpectedRunFailure)) return true;
        var leaves = error is AggregateException aggregate ? aggregate.Flatten().InnerExceptions.ToArray() : [error];
        return execution?.IsCanceled == true && ExpectedCancellation is { } token && token.IsCancellationRequested
            && leaves.All(leaf => leaf is OperationCanceledException canceled && canceled.CancellationToken == token);
    }
}
