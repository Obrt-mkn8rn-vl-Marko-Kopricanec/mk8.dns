using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TcpSessionResponseTests
{
    [Fact]
    public async Task OversizedAuthenticatedMaterialWritesOnlyTheCompleteEmptyServfailFrame()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true); CompleteTcpFixture.Install(f, 260);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var request = ClientRequestFixture.Request(type: 16); var stream = new TcpSessionStream(TcpSessionFixture.Frame(request)); await using var streamLifetime = stream.ConfigureAwait(true);
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer(), 1); await using var sessionLifetime = session.ConfigureAwait(true);
        var result = await session.RunAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientTcpSessionOutcome.MessageLimit, result.Outcome); Assert.Equal(1, result.RepliesWritten);
        ClientRequestFixture.AssertError(request, Assert.Single(TcpSessionFixture.Replies(stream)), 2);
        Assert.Equal(1, f.Resolver.Statistics.Entries); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
        Assert.Equal(2, f.Calls.Count); Assert.Equal(0, stream.DisposeCalls);
    }

    [Fact]
    public async Task BorrowedProcessorClosingDuringHeldAcquisitionDropsFrameWithoutStreamWrites()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var held = f.Hold(f.Question); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Override = (question, server, _) =>
        {
            if (question.Type == 48) return ValueTask.FromResult(f.Default(question, server));
            entered.TrySetResult(); return new ValueTask<Mk8.Dns.Domain.DnsUpstreamEvidence>(held.Task);
        };
        var frame = TcpSessionFixture.Frame(ClientRequestFixture.Request()); var stream = new TcpSessionStream([.. frame, .. frame]); await using var streamLifetime = stream.ConfigureAwait(true);
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer()); await using var sessionLifetime = session.ConfigureAwait(true);
        var running = session.RunAsync(CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var closing = processor.DisposeAsync().AsTask(); Assert.False(closing.IsCompleted);
            held.TrySetResult(f.Default(f.Question, AnchorRefreshFixture.Server));
            var result = await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecClientTcpSessionOutcome.Dropped, result.Outcome); Assert.Equal(1, result.MessagesRead); Assert.Equal(0, result.RepliesWritten);
            Assert.Empty(stream.Output); Assert.Equal(frame.Length, stream.BytesRead); Assert.Equal(0, stream.DisposeCalls);
            await closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        }
        finally { held.TrySetResult(f.Default(f.Question, AnchorRefreshFixture.Server)); }
    }

    [Fact]
    public async Task StreamAcknowledgementIsHistoricalAndDoesNotPromiseLeaseValidityDuringBackpressure()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var original = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var request = ClientRequestFixture.Request(); var stream = new TcpSessionStream(TcpSessionFixture.Frame(request)); await using var streamLifetime = stream.ConfigureAwait(true);
        stream.BeforeWrite = _ => { f.Advance(301); return Task.CompletedTask; };
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer(), 1); await using var sessionLifetime = session.ConfigureAwait(true);
        var result = await session.RunAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, result.RepliesWritten);
        Assert.False(DnssecClientResponseProjection.TryPrepare(original, f.Question, dnssecOk: true, out _));
        var historical = ClientMessageFixture.Decode(Assert.Single(TcpSessionFixture.Replies(stream)), DnsMessageCodec.DecodeQuery(request));
        Assert.All(historical.Answers, record => Assert.Equal(300U, record.Ttl)); Assert.Equal(2, f.Calls.Count);
    }
}
