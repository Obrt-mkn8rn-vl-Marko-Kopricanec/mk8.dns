using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NameserverDnssecBudgetTests
{
    [Fact]
    public async Task MutuallyDependentCutsTerminateWithoutChildOrProviderKeyFetch()
    {
        using var fixture = new NameserverDnssecFixture { CyclicProvider = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers);
        Assert.InRange(fixture.Calls.Count, 1, 20);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type == 48 && !call.Server.Equals(NameserverDnssecFixture.RootServer));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(6)]
    public async Task AddressDiscoveryConsumesTheOriginalExchangeBudget(int limit)
    {
        using var fixture = new NameserverDnssecFixture();
        var result = await fixture.Resolver(exchanges: limit).ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Equal(limit, fixture.Calls.Count); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(8)]
    public async Task AddressDiscoveryConsumesTheOriginalActualVerificationBudget(int limit)
    {
        using var fixture = new NameserverDnssecFixture(); var provider = new DnssecChainFixture.CountingVerifier();
        var result = await fixture.Resolver(attempts: limit, verifier: provider).ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Equal(limit, provider.Calls);
    }
}
