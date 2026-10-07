using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecHierarchyTests
{
    [Theory]
    [InlineData(15, DnssecResolutionOutcome.Authenticated, 47)]
    [InlineData(16, DnssecResolutionOutcome.Failure, 49)]
    public async Task ActualSelectedChainDepthCannotExceedInheritedKeyBound(int cuts, DnssecResolutionOutcome outcome, int calls)
    {
        using var fixture = new OnlineDnssecHierarchyFixture(cuts);
        var result = await fixture.Resolver().ResolveDnssecAsync(fixture.Question, CancellationToken.None);
        Assert.Equal(outcome, result.Outcome);
        Assert.Equal(calls, fixture.Calls);
        if (outcome == DnssecResolutionOutcome.Authenticated) Assert.Single(result.Answers);
        else Assert.Empty(result.Answers);
    }
}
