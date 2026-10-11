using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TcpSessionOwnershipTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task CloseJoinsAdmittedFrameAndPreventsNextFrameWithoutClosingBorrowedResources(int phase)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var frame = TcpSessionFixture.Frame(ClientRequestFixture.Request()); var stream = new TcpSessionStream([.. frame, .. frame]); await using var streamLifetime = stream.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task HoldAsync(CancellationToken token) { entered.TrySetResult(); await release.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(false); token.ThrowIfCancellationRequested(); }
        ConfigurePhase(f, stream, phase, HoldAsync);
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer(), 2);
        var running = session.RunAsync(CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await Assert.ThrowsAsync<InvalidOperationException>(() => session.RunAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
            var closing = session.DisposeAsync().AsTask(); Assert.Same(running, closing); Assert.Same(closing, session.DisposeAsync().AsTask());
            Assert.False(closing.IsCompleted); Assert.Equal(0, stream.DisposeCalls);
            release.TrySetResult(); var result = await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecClientTcpSessionOutcome.Stopped, result.Outcome); Assert.Equal(1, result.MessagesRead); Assert.Equal(1, result.RepliesWritten);
            Assert.Equal(frame.Length, stream.BytesRead); Assert.Single(TcpSessionFixture.Replies(stream)); Assert.Equal(0, processor.ActiveRequests);
            Assert.Equal(0, stream.DisposeCalls); Assert.Equal(2, f.Calls.Count);
        }
        finally { release.TrySetResult(); await TcpSessionFixture.SettleAsync(session).ConfigureAwait(true); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task ActualWriteOrFlushFaultIsSharedWithDisposalAndNeverRetries(int phase)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var frame = TcpSessionFixture.Frame(ClientRequestFixture.Request()); var stream = new TcpSessionStream([.. frame, .. frame]); await using var streamLifetime = stream.ConfigureAwait(true);
        static Task FailAsync(CancellationToken _) => Task.FromException(new IOException("Controlled stream fault."));
        if (phase == 0) stream.BeforeWrite = FailAsync; else stream.BeforeFlush = FailAsync;
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer());
        try
        {
            var running = session.RunAsync(CancellationToken.None).AsTask();
            await Assert.ThrowsAsync<IOException>(async () => await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).ConfigureAwait(true);
            Assert.Same(running, session.DisposeAsync().AsTask()); Assert.Equal(1, stream.WriteCalls);
            Assert.Equal(phase == 1 ? 1 : 0, stream.FlushCalls); Assert.Equal(frame.Length, stream.BytesRead);
            Assert.Equal(2, f.Calls.Count); Assert.Equal(0, processor.ActiveRequests); Assert.Equal(0, stream.DisposeCalls);
        }
        finally { await TcpSessionFixture.SettleAsync(session, typeof(IOException)).ConfigureAwait(true); }
    }

    [Fact]
    public async Task CancellationDoesNotReleaseAnActualIgnoringReadBeforeItSettles()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        using var caller = new CancellationTokenSource(); var stream = new TcpSessionStream(TcpSessionFixture.Frame(ClientRequestFixture.Request())); await using var streamLifetime = stream.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        stream.BeforeRead = async _ => { entered.TrySetResult(); await release.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(false); };
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer()); var running = session.RunAsync(caller.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await caller.CancelAsync().ConfigureAwait(true); var closing = session.DisposeAsync().AsTask();
            Assert.False(running.IsCompleted); Assert.Same(running, closing); Assert.False(closing.IsCompleted);
            release.TrySetResult();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).ConfigureAwait(true);
            Assert.Empty(f.Calls); Assert.Empty(stream.Output); Assert.Equal(0, stream.DisposeCalls);
        }
        finally { release.TrySetResult(); await TcpSessionFixture.SettleAsync(session, typeof(OperationCanceledException)).ConfigureAwait(true); }
    }
    private static void ConfigurePhase(ClientProofEpochFixture fixture, TcpSessionStream stream, int phase, Func<CancellationToken, Task> holdAsync)
    {
        if (phase == 0) stream.BeforeRead = holdAsync;
        if (phase == 2) stream.BeforeWrite = holdAsync;
        if (phase == 3) stream.BeforeFlush = holdAsync;
        if (phase == 1)
        {
            fixture.Override = async (question, server, token) =>
            {
                if (question.Type != 48) await holdAsync(token).ConfigureAwait(false);
                return fixture.Default(question, server);
            };
        }
    }

}
