using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CheckingDisabledMaterialAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task MismatchedQuestionEndpointDoOrCdRefusesWithoutValidation(int mismatch)
    {
        var f = new CheckingDisabledMaterialFixture(exchanges: 1); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, server, _) =>
        {
            var data = new DnsRecord(question.Name, 1, 300, [192, 0, 2, 42]);
            return ValueTask.FromResult(new DnsUpstreamEvidence(mismatch == 0 ? question with { Name = DnsName.Parse("foreign.example.") } : question,
                mismatch == 1 ? new DnsServerEndpoint([192, 0, 2, 99], 53) : server, 1, mismatch == 3 ? (ushort)0x8400 : (ushort)0x8410,
                0, hasEdns: true, 1232, 0, mismatch == 2 ? (ushort)0 : (ushort)0x8000, [data, f.Signature(data)], [], []));
        };
        var reply = await f.Processor.ProcessAsync(CheckingDisabledMaterialFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Failure, reply.Outcome); Assert.Single(f.Upstream.Calls);
        Assert.Empty(f.Epoch.Calls); Assert.Equal(0, f.Epoch.Verifier.Calls);
    }

    [Fact]
    public async Task DefaultSourceStillRefusesDoBeforeAcquisitionAndDeniedPeerDoesNoWork()
    {
        var legacy = new CheckingDisabledFixture(); await using var oldLifetime = legacy.ConfigureAwait(true);
        var refused = await legacy.Processor.ProcessAsync(CheckingDisabledMaterialFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Unsupported, refused.Outcome); Assert.Empty(legacy.Upstream.Calls);
        var f = new CheckingDisabledMaterialFixture(); await using var lifetime = f.ConfigureAwait(true);
        var denied = await f.Processor.ProcessAsync(CheckingDisabledMaterialFixture.Request(), new byte[] { 198, 51, 100, 1 }, tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Denied, denied.Outcome); Assert.Empty(f.Upstream.Calls); Assert.Empty(f.Epoch.Calls);
    }

    [Fact]
    public async Task CloseAndQuotaRetainActualBorrowedAcquisitionUntilSettlement()
    {
        var f = new CheckingDisabledMaterialFixture(requests: 1); await using var lifetime = f.ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Override = (_, _, _) => { entered.SetResult(); return new ValueTask<DnsUpstreamEvidence>(held.Task); };
        var running = f.Processor.ProcessAsync(CheckingDisabledMaterialFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).AsTask();
        Task? closing = null;
        try
        {
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var full = await f.Processor.ProcessAsync(CheckingDisabledMaterialFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecClientReplyOutcome.Overloaded, full.Outcome);
            closing = f.Processor.DisposeAsync().AsTask(); Assert.False(closing.IsCompleted); Assert.Equal(1, f.Processor.ActiveRequests);
        }
        finally
        {
            var record = new DnsRecord(f.Epoch.Question.Name, 1, 300, [192, 0, 2, 42]);
            held.TrySetResult(CheckingDisabledMaterialFixture.Reply(f.Epoch.Question, AnchorRefreshFixture.Server, [record, f.Signature(record)]));
            await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            if (closing is not null) await closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        }
        Assert.Equal(DnssecClientReplyOutcome.Closed, (await running.ConfigureAwait(true)).Outcome); Assert.Equal(0, f.Processor.ActiveRequests);
    }
}
