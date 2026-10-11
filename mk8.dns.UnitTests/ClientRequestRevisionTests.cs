using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientRequestRevisionTests
{
    [Theory]
    [InlineData(18)]
    [InlineData(19)]
    public async Task ActualAcknowledgementDuringFinalWirePreparationDiscardsOldPacket(int wireRead)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f, ad: true); await using var processorLifetime = processor.ConfigureAwait(true);
        var request = ClientRequestFixture.Request(); var query = DnsMessageCodec.DecodeQuery(request);
        Assert.Equal(DnssecClientReplyOutcome.Encoded,
            (await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true)).Outcome);
        using var release = new ManualResetEventSlim(); using var acknowledged = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Anchors.Store.BeforeCommit = () =>
        {
            entered.TrySetResult();
            if (!release.Wait(AnchorRefreshFixture.Timeout, CancellationToken.None)) throw new TimeoutException("Client commit not released.");
        };
        var refresh = Task.Run(async () =>
        {
            var outcome = await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(false);
            acknowledged.Set(); return outcome;
        });
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var baseline = f.Clock.Reads; var triggered = false;
            f.Clock.BeforeTimestamp = read =>
            {
                if (read != baseline + wireRead) return;
                triggered = true; release.Set();
                if (!acknowledged.Wait(AnchorRefreshFixture.Timeout, CancellationToken.None)) throw new TimeoutException("Client ACK did not settle.");
            };
            var reply = await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
            Assert.True(triggered); Assert.Equal(DnssecClientReplyOutcome.Failure, reply.Outcome); Assert.Null(reply.Revision);
            AssertRefusal(f, processor, reply, query);
        }
        finally
        {
            f.Clock.BeforeTimestamp = null; release.Set();
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied,
                await refresh.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true));
        }
    }
    private static void AssertRefusal(ClientProofEpochFixture f, DnssecClientRequestProcessor processor,
        DnssecClientReply reply, Mk8.Dns.Domain.DnsQuery query)
    {
        var decoded = ClientMessageFixture.Decode(reply.GetMessage(), query);
        Assert.Equal(2, decoded.ResponseCode); Assert.Equal(0, decoded.Flags & 32); Assert.Empty(decoded.Answers);
        Assert.Equal(2, f.Calls.Count); Assert.Equal(2, f.Resolver.Statistics.Revision); Assert.Equal(0, processor.ActiveRequests);
    }

}
