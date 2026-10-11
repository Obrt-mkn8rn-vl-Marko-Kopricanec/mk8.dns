using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientRequestOwnershipTests
{
    [Fact]
    public async Task ClosingJoinsTheAdmittedCallWithoutCancelingOrDisposingItsSource()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f, requests: 1); await using var processorLifetime = processor.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        CancellationToken actual = default;
        f.Override = (question, server, token) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Default(question, server));
            actual = token; entered.TrySetResult(); return new(held.Task);
        };
        var pending = processor.ProcessAsync(ClientRequestFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await CloseAndCompleteAsync(f, processor, held, keys, pending, actual).ConfigureAwait(true);
        }
        finally
        {
            held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
            await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        }
        f.Override = null;
        Assert.NotNull((await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).ClientProof);
    }

    private static async Task CloseAndCompleteAsync(ClientProofEpochFixture f, DnssecClientRequestProcessor processor,
        TaskCompletionSource<DnsUpstreamEvidence> held, DnsQuestion keys,
        Task<DnssecClientReply> pending, CancellationToken actual)
    {
        var busy = await processor.ProcessAsync(ClientRequestFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Overloaded, busy.Outcome); Assert.Empty(busy.GetMessage()); Assert.Single(f.Calls);
        var closing = processor.DisposeAsync().AsTask(); Assert.Same(closing, processor.DisposeAsync().AsTask());
        Assert.False(closing.IsCompleted); Assert.False(actual.IsCancellationRequested); Assert.Equal(1, processor.ActiveRequests);
        held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
        var reply = await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Closed, reply.Outcome); Assert.Empty(reply.GetMessage());
        await closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, f.Resolver.Statistics.Entries); Assert.Equal(0, processor.ActiveRequests);
    }

    [Fact]
    public async Task CanceledWaiterMayDetachWhileBorrowedCoalescerStillOwnsActualWorker()
    {
        var f = new ClientProofEpochFixture(coalesced: true, workers: 1); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keys = new DnsQuestion(f.Anchors.Keys.Origin, 48, 1); var held = f.Hold(keys);
        f.Override = (question, server, _) =>
        {
            if (question.Type != 48) return ValueTask.FromResult(f.Default(question, server));
            entered.TrySetResult(); return new(held.Task);
        };
        using var caller = new CancellationTokenSource();
        var pending = processor.ProcessAsync(ClientRequestFixture.Request(), ClientRequestFixture.Peer(), tcp: true, caller.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await caller.CancelAsync().ConfigureAwait(true);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout,
                TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.Equal(0, processor.ActiveRequests); Assert.Equal(1, f.Resolver.ActiveWorkers);
            await processor.DisposeAsync().ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Failure,
                (await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
            Assert.Single(f.Calls); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
        }
        finally
        {
            await caller.CancelAsync().ConfigureAwait(true); held.TrySetResult(f.Default(keys, AnchorRefreshFixture.Server));
            try { await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
            catch (OperationCanceledException) { }
            await CoalescedTrustEpochFixture.WaitUntilAsync(() => f.Resolver.ActiveWorkers == 0).ConfigureAwait(true);
        }
        Assert.Equal(0, f.Timers.ActiveTimers);
    }

    [Fact]
    public async Task PropagatedProviderFaultSettlesTheRequestWithoutSyntheticFailureState()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (_, _, _) => throw new InvalidOperationException("Controlled actual provider fault.");
        var processor = ClientRequestFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => processor.ProcessAsync(ClientRequestFixture.Request(),
            ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, processor.ActiveRequests); Assert.Equal(0, f.Resolver.Statistics.SourceRequests);
        Assert.Equal(0, f.Resolver.Statistics.Entries); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
        f.Override = null;
        Assert.Equal(DnssecClientReplyOutcome.Encoded,
            (await processor.ProcessAsync(ClientRequestFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true)).Outcome);
    }
}
