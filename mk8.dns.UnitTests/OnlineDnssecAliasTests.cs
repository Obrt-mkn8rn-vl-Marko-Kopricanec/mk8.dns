using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecAliasTests
{
    [Theory]
    [InlineData("www.example.")]
    [InlineData("www.child.example.")]
    [InlineData("missing.example.")]
    [InlineData("missing.child.example.")]
    public async Task CnameRestartsAndAuthenticatesEveryActualTarget(string target)
    {
        ArgumentNullException.ThrowIfNull(target);
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("alias.example."), 5, 300, DnsName.Parse(target).ToWire()));
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("alias.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(5, result.Answers[0].Type);
        Assert.Contains(fixture.Calls, call => call.Question.Name.Equals(DnsName.Parse(target)) && call.Server.Equals(OnlineDnssecFixture.RootServer));
        Assert.Equal(target.StartsWith("missing", StringComparison.Ordinal) ? 3 : 0, result.ResponseCode);
    }

    [Fact]
    public async Task InlineTargetDataCannotBypassNewTargetLookup()
    {
        using var fixture = new OnlineDnssecFixture();
        var alias = DnsName.Parse("alias.example.");
        fixture.RootRecords.Add(new DnsRecord(alias, 5, 300, DnsName.Parse("www.child.example.").ToWire()));
        fixture.Transform = reply => reply.Question.Name.Equals(alias)
            ? OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers, DnssecFixture.A("www.child.example.", 99)]) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(alias, 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(1, result.Answers[^1].GetData()[^1]);
        Assert.Contains(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer) && call.Question.Type == 48);
    }

    [Theory]
    [InlineData(1, DnssecResolutionOutcome.Failure)]
    [InlineData(5, DnssecResolutionOutcome.Authenticated)]
    public async Task ExplicitCnameMayDescribeUnservedTargetButCannotFollowOutsideAnchor(int type, DnssecResolutionOutcome expected)
    {
        using var fixture = new OnlineDnssecFixture();
        var alias = DnsName.Parse("alias.example.");
        fixture.RootRecords.Add(new DnsRecord(alias, 5, 300, DnsName.Parse("target.other.").ToWire()));
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(alias, (ushort)type, 1), CancellationToken.None);
        Assert.Equal(expected, result.Outcome);
        Assert.Equal(2, fixture.Calls.Count);
        if (expected == DnssecResolutionOutcome.Failure) Assert.Empty(result.Answers);
        else Assert.Equal(5, Assert.Single(result.Answers).Type);
    }

    [Theory]
    [InlineData("a.example.")]
    [InlineData("b.example.")]
    public async Task AliasCyclesDiscardAccumulatedData(string start)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("a.example."), 5, 300, DnsName.Parse("b.example.").ToWire()));
        fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("b.example."), 5, 300, DnsName.Parse("a.example.").ToWire()));
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse(start), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Equal(3, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    public async Task ExpandedWildcardNeedsAuthenticatedClosestEncloserProof(int type)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = new DnsQuestion(DnsName.Parse("b.example."), (ushort)type, 1);
        var literal = type == 5 ? new DnsRecord(DnsName.Parse("*.example."), 5, 300, DnsName.Parse("www.example.").ToWire())
            : DnssecFixture.A("*.example.");
        var nsec = OnlineDnssecFixture.Nsec(literal.Owner, DnsName.Parse("z.example."), (ushort)type);
        var signature = fixture.Sign([literal]).WithOwner(question.Name);
        fixture.Transform = reply => reply.Question.Equals(question)
            ? OnlineDnssecFixture.Reply(question, reply.Server, [literal.WithOwner(question.Name), signature], [nsec, fixture.Sign([nsec])]) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(type, Assert.Single(result.Answers).Type);
    }

    [Fact]
    public async Task ExpandedPositiveWithoutNsecNeverBecomesExactAuthentication()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = new DnsQuestion(DnsName.Parse("b.example."), 1, 1);
        var literal = DnssecFixture.A("*.example.");
        fixture.Transform = reply => reply.Question.Equals(question)
            ? OnlineDnssecFixture.Reply(question, reply.Server, [literal.WithOwner(question.Name), fixture.Sign([literal]).WithOwner(question.Name)]) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }

    [Fact]
    public async Task DnameDescendantDoesNotReceiveAnUnvalidatedSyntheticCname()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = new DnsQuestion(DnsName.Parse("a.branch.example."), 1, 1);
        var dname = new DnsRecord(DnsName.Parse("branch.example."), 39, 300, DnsName.Parse("other.example.").ToWire());
        fixture.Transform = reply => reply.Question.Equals(question)
            ? OnlineDnssecFixture.Reply(question, reply.Server, [dname, fixture.Sign([dname])]) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }
}
