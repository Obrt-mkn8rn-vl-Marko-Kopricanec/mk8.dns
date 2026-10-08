using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OperationCutTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task AliasRestartCannotAcceptAncestorDataNegativeOrAliasAcrossAnEarlierCut(int response)
    {
        using var fixture = new OperationCutFixture { ParentTarget = response };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Fact]
    public async Task AliasRestartCanFollowSameCutAndAuthenticateChildTarget()
    {
        using var fixture = new OperationCutFixture { ChildTarget = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(new ushort[] { 5, 1 }, result.Answers.Select(record => record.Type));
        Assert.Equal(OperationCutFixture.Target, result.Answers[^1].Owner);
    }

    [Fact]
    public async Task SeparateResolutionDoesNotReusePriorOperationCuts()
    {
        using var fixture = new OperationCutFixture { ChildTarget = true };
        var resolver = fixture.Resolver();
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(OperationCutFixture.Question, CancellationToken.None)).Outcome);
        fixture.ParentTarget = 1;
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(new DnsQuestion(OperationCutFixture.Target, 1, 1), CancellationToken.None)).Outcome);
    }
}
