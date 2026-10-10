using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofEpochRevisionTests
{
    [Theory]
    [InlineData(14)]
    [InlineData(15)]
    public async Task ActualAcknowledgementDuringMaterializationRefusesTheOldCohort(int deliveryRead)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        Assert.NotNull((await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).ClientProof);
        var calls = f.Calls.Count; var crypto = f.Verifier.Calls;
        using var release = new ManualResetEventSlim(); using var acknowledged = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Anchors.Store.BeforeCommit = () =>
        {
            entered.TrySetResult();
            if (!release.Wait(AnchorRefreshFixture.Timeout, CancellationToken.None)) throw new TimeoutException("Controlled commit not released.");
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
                if (read != baseline + deliveryRead) return;
                triggered = true; release.Set();
                if (!acknowledged.Wait(AnchorRefreshFixture.Timeout, CancellationToken.None)) throw new TimeoutException("Actual acknowledgement did not settle.");
            };
            var result = await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true);
            Assert.True(triggered); Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
            AssertRetired(f, result, calls, crypto);
        }
        finally
        {
            f.Clock.BeforeTimestamp = null; release.Set();
            Assert.Equal(DnssecAnchorRefreshOutcome.Applied,
                await refresh.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true));
        }
    }
    private static void AssertRetired(ClientProofEpochFixture f, DnssecResolutionResult result, int calls, int crypto)
    {
        Assert.Empty(result.Answers); Assert.Null(result.ClientProof);
        Assert.Equal(calls, f.Calls.Count); Assert.Equal(crypto, f.Verifier.Calls);
        Assert.Equal(2, f.Resolver.Statistics.Revision); Assert.Equal(0, f.Resolver.Statistics.Entries);
        Assert.Equal(0, f.Resolver.Statistics.ActiveRequests); Assert.Equal(0, f.Resolver.Statistics.RetiredProfiles);
    }

}
