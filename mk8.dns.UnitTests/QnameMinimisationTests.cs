using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class QnameMinimisationTests
{
    private static readonly string[] ChildNames = ["child.example.", "secret.child.example.", "secret.child.example."];
    private static readonly string[] DeepNames = ["example.", "team.example.", "private.team.example.", "private.team.example."];
    [Theory]
    [InlineData(1)]
    [InlineData(28)]
    public async Task AncestorReceivesOnlyTheNextLabelAndNotTheOriginalType(ushort type)
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("secret.child.example.", child: true, type);
        var question = new DnsQuestion(DnsName.Parse("secret.child.example."), type, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(type, Assert.Single(result.Answers).Type);
        Assert.Equal(new ushort[] { 48, 2, 43 }, fixture.Calls.Where(call => call.Server.Equals(OnlineDnssecFixture.RootServer)).Select(call => call.Question.Type));
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.RootServer) && call.Question.Name.Equals(question.Name));
        Assert.Equal(ChildNames,
            fixture.Calls.Where(call => call.Server.Equals(OnlineDnssecFixture.ChildServer)).Select(call => call.Question.Name.ToString()), StringComparer.Ordinal);
        Assert.Empty(result.Authority);
    }

    [Fact]
    public async Task NonDelegatedLabelsAdvanceOneAtATime()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.team.example.");
        var question = new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(DeepNames, fixture.Calls.Select(call => call.Question.Name.ToString()), StringComparer.Ordinal);
        Assert.Equal(new ushort[] { 48, 2, 2, 1 }, fixture.Calls.Select(call => call.Question.Type));
        Assert.Single(result.Answers); Assert.Empty(result.Authority);
    }

    [Fact]
    public async Task ExactParentSideDsDoesNotProbeOrFetchTheChild()
    {
        using var fixture = new QnameMinimisationFixture();
        var question = new DnsQuestion(fixture.Source.Child, 43, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal((ushort)43, Assert.Single(result.Answers).Type);
        Assert.Equal(new ushort[] { 48, 43 }, fixture.Calls.Select(call => call.Question.Type));
    }

    [Fact]
    public async Task ExplicitNsUsesItsOriginalQuestionWithoutDuplicatingTheProbe()
    {
        using var fixture = new QnameMinimisationFixture();
        var question = new DnsQuestion(DnsName.Parse("team.example."), 2, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(2, fixture.Calls.Count);
        Assert.Empty(result.Answers); Assert.Single(result.Authority);
    }

    [Fact]
    public async Task AliasRestartsMinimisationAndKeepsAuthenticatedCuts()
    {
        using var fixture = new QnameMinimisationFixture();
        fixture.AddAlias("start.child.example.", "target.child.example."); fixture.AddAddress("target.child.example.", child: true);
        var question = new DnsQuestion(DnsName.Parse("start.child.example."), 1, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(new ushort[] { 5, 1 }, result.Answers.Select(record => record.Type));
        Assert.Equal(2, fixture.Calls.Count(call => call.Server.Equals(OnlineDnssecFixture.RootServer) && call.Question.Type == 2));
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.RootServer) && call.Question.Name.Equals(question.Name));
    }

    [Fact]
    public async Task AuthenticatedUnsignedCutRemainsAnEmptyMarker()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.Source.UnsignedChild = true;
        var question = new DnsQuestion(DnsName.Parse("secret.child.example."), 1, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.UnsignedDelegation, result.Outcome);
        Assert.Equal(fixture.Source.Child, result.UnsignedDelegation);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    [InlineData(128)]
    public void PolicyOwnsAValidImmutableStepLimit(int steps)
        => Assert.Equal(steps, new DnsQnameMinimisationPolicy(steps).MaximumSteps);

    [Theory]
    [InlineData(0)]
    [InlineData(129)]
    public void InvalidStepLimitIsRefused(int steps)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new DnsQnameMinimisationPolicy(steps));
}
