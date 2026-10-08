using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecDnameBudgetTests
{
    [Theory]
    [InlineData(2, DnssecResolutionOutcome.Failure)]
    [InlineData(3, DnssecResolutionOutcome.Authenticated)]
    public async Task DnameTargetUsesSharedExchangeBudget(int exchanges, DnssecResolutionOutcome expected)
    {
        using var fixture = new OnlineDnssecDnameFixture();
        var result = await fixture.Zones.Resolver(exchanges: exchanges).ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(expected, result.Outcome);
        Assert.Equal(exchanges, fixture.Zones.Calls.Count);
        if (expected == DnssecResolutionOutcome.Failure) Assert.Empty(result.Answers);
    }

    [Theory]
    [InlineData(4, DnssecResolutionOutcome.Failure)]
    [InlineData(5, DnssecResolutionOutcome.Authenticated)]
    public async Task DnameAndTargetFinalReauthenticationUseSharedActualProviderBudget(int attempts, DnssecResolutionOutcome expected)
    {
        using var fixture = new OnlineDnssecDnameFixture();
        var verifier = new DnssecChainFixture.CountingVerifier();
        var result = await fixture.Zones.Resolver(attempts: attempts, verifier: verifier)
            .ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(expected, result.Outcome);
        Assert.Equal(attempts, verifier.Calls);
        if (expected == DnssecResolutionOutcome.Failure) Assert.Empty(result.Answers);
    }

    [Fact]
    public async Task CancelledDnameTargetRetainsActualIgnoringProviderUntilCompletion()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        using var cancellation = new CancellationTokenSource();
        var completion = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        var target = new DnsQuestion(DnsName.Parse("www.example."), 1, 1);
        fixture.Zones.Override = (question, server, _) => question.Equals(target)
            ? new ValueTask<DnsUpstreamEvidence>(completion.Task)
            : ValueTask.FromResult(fixture.Zones.Transform!(fixture.Zones.Default(question, server)));
        var operation = fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), cancellation.Token).AsTask();
        try
        {
            Assert.Equal(3, fixture.Zones.Calls.Count);
            await cancellation.CancelAsync();
            Assert.False(operation.IsCompleted);
        }
        finally
        {
            completion.TrySetResult(fixture.Zones.Default(target, OnlineDnssecFixture.RootServer));
            OperationCanceledException? terminal = null;
            try { await operation.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException error) { terminal = error; }
            Assert.IsAssignableFrom<OperationCanceledException>(terminal);
        }
    }
}
