using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthorityBacktrackingBudgetTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(8)]
    public async Task FailedBranchesCannotRefundExchanges(int limit)
    {
        using var fixture = new AuthorityBacktrackingFixture();
        var result = await fixture.Resolver(exchanges: limit).ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Equal(limit, fixture.Calls.Count); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(7)]
    public async Task FailedBranchesCannotRefundActualVerificationAttempts(int limit)
    {
        using var fixture = new AuthorityBacktrackingFixture(); var verifier = new DnssecChainFixture.CountingVerifier();
        var result = await fixture.Resolver(attempts: limit, verifier: verifier).ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Equal(limit, verifier.Calls);
    }

    [Fact]
    public async Task ExpiredParentKeysCannotAuthorizeAnAlternateBranch()
    {
        using var fixture = new AuthorityBacktrackingFixture();
        fixture.BadReply = (_, _) => { fixture.Source.Clock.Advance(301); return ValueTask.FromResult<DnsUpstreamEvidence>(null!); };
        var result = await fixture.Resolver().ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(AuthorityBacktrackingFixture.AlternateRoot));
    }

    [Fact]
    public async Task CancellationRetainsTheActualProviderUntilItCompletes()
    {
        using var fixture = new AuthorityBacktrackingFixture(); using var cancel = new CancellationTokenSource();
        TaskCompletionSource<DnsUpstreamEvidence> release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.BadReply = (_, _) => new ValueTask<DnsUpstreamEvidence>(release.Task);
        var task = fixture.Resolver().ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, cancel.Token).AsTask();
        try
        {
            Assert.Equal(5, fixture.Calls.Count);
            await cancel.CancelAsync(); Assert.False(task.IsCompleted);
        }
        finally { release.TrySetResult(null!); }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task.WaitAsync(CancellationToken.None));
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(AuthorityBacktrackingFixture.AlternateRoot));
    }
}
