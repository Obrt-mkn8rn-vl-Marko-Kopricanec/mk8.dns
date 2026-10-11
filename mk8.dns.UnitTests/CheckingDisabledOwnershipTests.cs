using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CheckingDisabledOwnershipTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualUncheckedProviderRetainsRequestAndCloseUntilSettlement(bool cancel)
    {
        var f = new CheckingDisabledFixture(requests: 1); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsAnswer>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken actual = default;
        f.Override = (_, token) => { actual = token; entered.TrySetResult(); return new(held.Task); };
        using var caller = new CancellationTokenSource();
        var pending = f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, caller.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(1, f.Processor.ActiveRequests);
            Assert.Equal(DnssecClientReplyOutcome.Overloaded,
                (await f.Processor.ProcessAsync(ClientRequestFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true)).Outcome);
            var closing = f.Processor.DisposeAsync().AsTask(); Assert.Same(closing, f.Processor.DisposeAsync().AsTask());
            if (cancel) await caller.CancelAsync().ConfigureAwait(true);
            Assert.False(pending.IsCompleted); Assert.False(closing.IsCompleted); Assert.Equal(cancel, actual.IsCancellationRequested);
            held.TrySetResult(f.Answer(f.Epoch.Question));
            if (cancel)
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(AnchorRefreshFixture.Timeout,
                    TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            }
            else { var reply = await pending.ConfigureAwait(true); Assert.Equal(DnssecClientReplyOutcome.Closed, reply.Outcome); Assert.Empty(reply.GetMessage()); }
            await closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        }
        finally
        {
            held.TrySetResult(f.Answer(f.Epoch.Question));
            try { await pending.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
            catch (OperationCanceledException) when (caller.IsCancellationRequested) { }
        }
        f.Override = null; Assert.Equal(0, f.Processor.ActiveRequests); Assert.Empty(f.Epoch.Calls);
        Assert.Equal(0, (await f.Unchecked.ResolveAsync(f.Epoch.Question, CancellationToken.None).ConfigureAwait(true)).ResponseCode);
        Assert.Equal(DnssecResolutionOutcome.Authenticated,
            (await f.Epoch.Resolver.ResolveDnssecAsync(f.Epoch.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
    }

    [Fact]
    public async Task UnexpectedProviderFaultPropagatesWithoutValidationFailureState()
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (_, _) => throw new InvalidOperationException("Controlled nonvalidating provider fault.");
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Processor.ProcessAsync(CheckingDisabledFixture.Request(),
            ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, f.Processor.ActiveRequests); Assert.Equal(0, f.Epoch.Resolver.Statistics.FailureEntries); Assert.Empty(f.Epoch.Calls);
        f.Override = null;
        Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled,
            (await f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true)).Outcome);
    }
}
