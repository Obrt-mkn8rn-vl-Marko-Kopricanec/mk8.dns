using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NameserverDnssecDepthTests
{
    [Theory]
    [InlineData(7, DnssecResolutionOutcome.Authenticated)]
    [InlineData(8, DnssecResolutionOutcome.Failure)]
    public async Task NestedDependencyDepthHasAnActualEightCutBoundary(int dependencies, DnssecResolutionOutcome expected)
    {
        using var fixture = new NameserverDnssecDepthFixture(dependencies);
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(expected, result.Outcome); Assert.InRange(fixture.Calls, 1, 128);
        if (expected == DnssecResolutionOutcome.Authenticated) Assert.Single(result.Answers);
        else { Assert.Empty(result.Answers); Assert.Empty(result.Authority); }
    }
}
