using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OperationCutAdmissionTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task DnameRestartRetainsTheEarlierChildBoundary(int response)
    {
        using var fixture = new OperationCutFixture { Dname = true, ParentTarget = response };
        var result = await fixture.Resolver().ResolveDnssecAsync(fixture.Query, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Fact]
    public async Task DnameCanSynthesizeAndChaseThroughTheSameAuthenticatedCut()
    {
        using var fixture = new OperationCutFixture { Dname = true, ChildTarget = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(fixture.Query, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(new ushort[] { 39, 5, 1 }, result.Answers.Select(record => record.Type));
        Assert.Equal(OperationCutFixture.Target, result.Answers[^1].Owner);
    }

    [Fact]
    public async Task ParentSideExactDsRemainsPermittedAfterAnAliasRestart()
    {
        using var fixture = new OperationCutFixture();
        fixture.Transform = reply =>
        {
            if (!reply.Server.Equals(OnlineDnssecFixture.ChildServer) || !reply.Question.Name.Equals(OperationCutFixture.Alias)) return reply;
            var record = new DnsRecord(OperationCutFixture.Alias, 5, 300, fixture.Source.Child.ToWire());
            return OnlineDnssecFixture.Copy(reply, answers: [record, fixture.Source.Sign([record], child: true)]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutFixture.Question with { Type = 43 }, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(new ushort[] { 5, 43 }, result.Answers.Select(record => record.Type));
        Assert.Equal(fixture.Source.Root, result.Origin);
    }

    [Fact]
    public async Task ExplicitCnameDoesNotChaseOrConsultAncestorTargetData()
    {
        using var fixture = new OperationCutFixture { ParentTarget = 1 };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutFixture.Question with { Type = 5 }, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome); Assert.Equal(5, Assert.Single(result.Answers).Type);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Name.Equals(OperationCutFixture.Target));
    }

    [Fact]
    public async Task OppositeSignedAndUnsignedReceiptsForTheSameCutRefuseInsteadOfChangingPolicy()
    {
        using var fixture = new OperationCutDependencyFixture { ParentAddress = false, UnsignedProvider = true, SignedOnAaaa = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutDependencyFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OperationCutDependencyFixture.Provider) && call.Question.Type == 48);
    }

    [Fact]
    public async Task SignedCutCannotBecomeAnUnsignedMarkerAfterAFailedChildBranch()
    {
        using var fixture = new AuthorityBacktrackingFixture();
        fixture.AlternateReply = reply => reply.Question.Type == 43 ? fixture.Source.Unsigned(reply.Question, reply.Server) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Null(result.UnsignedDelegation);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }

    [Fact]
    public async Task AliasOutsideTheStaticIslandStillDiscardsAccumulatedData()
    {
        using var fixture = new OperationCutFixture();
        fixture.Transform = reply =>
        {
            if (!reply.Server.Equals(OnlineDnssecFixture.ChildServer) || !reply.Question.Name.Equals(OperationCutFixture.Alias)) return reply;
            var alias = new DnsRecord(OperationCutFixture.Alias, 5, 300, DnsName.Parse("outside.").ToWire());
            return OnlineDnssecFixture.Copy(reply, answers: [alias, fixture.Source.Sign([alias], child: true)]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(OperationCutFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }
}
