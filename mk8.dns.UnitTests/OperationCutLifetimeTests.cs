using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OperationCutLifetimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReceiptFromFailedAddressBranchIsWindowFencedAtFinalOutput(bool rollback)
    {
        using var fixture = new OperationCutDependencyFixture { ParentAddress = false, FirstProviderDsWindow = new DnssecSignatureWindow(100, 103) };
        fixture.AfterAddressFailure = () => fixture.Clock.SetWall(104);
        var dsCalls = 0;
        fixture.Transform = reply =>
        {
            if (rollback && reply.Question.Type == 43 && reply.Question.Name.Equals(DnsName.Parse("provider.example.")) && ++dsCalls == 2) fixture.Clock.SetWall(100);
            return reply;
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutDependencyFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);

    }

    [Fact]
    public async Task DuplicateCutReceiptKeepsFirstShortLifetimeWithoutLeakingDsToClient()
    {
        using var fixture = new OperationCutDependencyFixture { ParentAddress = false, FirstProviderDsWindow = new DnssecSignatureWindow(100, 103) };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutDependencyFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(3U, result.AuthenticatedTtl); Assert.Equal(3U, Assert.Single(result.Answers).Ttl);
        Assert.Empty(result.Authority); Assert.DoesNotContain(result.Answers, record => record.Type == 43);
    }

    [Fact]
    public async Task AlreadyAdmittedProviderRemainsJoinedThroughCancellationAfterCutAdmission()
    {
        using var fixture = new OperationCutFixture(); using var cancellation = new CancellationTokenSource();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.TargetReply = _ => new ValueTask<DnsUpstreamEvidence>(held.Task);
        var operation = fixture.Resolver().ResolveDnssecAsync(OperationCutFixture.Question, cancellation.Token).AsTask();
        try
        {
            Assert.False(operation.IsCompleted);
            Assert.Contains(fixture.Calls, call => call.Question.Name.Equals(fixture.Source.Child) && call.Question.Type == 43);
            await cancellation.CancelAsync().ConfigureAwait(true);
            Assert.False(operation.IsCompleted);
        }
        finally { held.TrySetResult(null!); }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5))).ConfigureAwait(true);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(11)]
    public async Task RetainedReceiptVerificationConsumesTheOriginalActualAttemptBudget(int attempts)
    {
        using var fixture = new OperationCutFixture { ChildTarget = true };
        var result = await fixture.Resolver(attempts: attempts).ResolveDnssecAsync(OperationCutFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }
}
