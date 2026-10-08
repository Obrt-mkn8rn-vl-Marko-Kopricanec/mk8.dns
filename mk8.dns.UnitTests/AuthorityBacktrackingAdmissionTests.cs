using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthorityBacktrackingAdmissionTests
{
    [Fact]
    public async Task AnAlternateReferralCannotSkipAnAuthenticatedIntermediateCut()
    {
        using var fixture = new AuthorityBacktrackingFixture();
        var target = new DnsQuestion(DnsName.Parse("www.inner.child.example."), 1, 1);
        var inner = DnsName.Parse("inner.child.example."); var ns = inner.PrependLabel("ns"u8);
        fixture.AlternateReply = reply => reply.Question.Equals(target)
            ? OnlineDnssecFixture.Reply(target, reply.Server, [], [new DnsRecord(inner, 2, 300, ns.ToWire())],
                [new DnsRecord(ns, 1, 300, OnlineDnssecFixture.ChildServer.GetAddress())], authoritative: false) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(target, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Name.Equals(inner) && call.Question.Type == 43);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AlternateParentCannotAnswerFromAboveAnAuthenticatedDelegation(bool failKeys)
    {
        using var fixture = new AuthorityBacktrackingFixture();
        fixture.AlternateReply = reply => reply.Question.Equals(AuthorityBacktrackingFixture.Question)
            ? OnlineDnssecFixture.Reply(reply.Question, reply.Server,
                [fixture.Source.ChildRecords[0], fixture.Source.Sign([fixture.Source.ChildRecords[0]])]) : reply;
        if (failKeys) fixture.BadKeyReply = true;
        var result = await fixture.Resolver().ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }

    [Theory]
    [InlineData("www.child.example.", 28, 0)]
    [InlineData("missing.child.example.", 1, 3)]
    public async Task AlternateBranchNegativeMustAuthenticateAtTheSelectedChild(string name, int type, int code)
    {
        using var fixture = new AuthorityBacktrackingFixture();
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse(name), (ushort)type, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome); Assert.Equal(code, result.ResponseCode);
        Assert.Empty(result.Answers); Assert.Equal(fixture.Source.Child, Assert.Single(result.Authority).Owner);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthenticatedAliasSurvivesOnlyASuccessfulAlternateBranch(bool negative)
    {
        using var fixture = new AuthorityBacktrackingFixture(); var alias = DnsName.Parse("alias.example.");
        var target = DnsName.Parse(negative ? "missing.child.example." : "www.child.example.");
        fixture.Source.RootRecords.Add(new DnsRecord(alias, 5, 300, target.ToWire()));
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(alias, 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome); Assert.Equal(negative ? 3 : 0, result.ResponseCode);
        Assert.Equal(alias, result.Answers[0].Owner); Assert.Equal(5, result.Answers[0].Type);
        if (negative) Assert.Single(result.Answers);
        else Assert.Equal(target, result.Answers[^1].Owner);
    }

    [Fact]
    public async Task ForgedDsOnTheAlternateParentCannotAuthenticateTheGoodChild()
    {
        using var fixture = new AuthorityBacktrackingFixture();
        fixture.AlternateReply = reply => reply.Question.Type == 43 ? OnlineDnssecFixture.Copy(reply,
            answers: reply.Answers.Where(record => record.Type != 46).ToArray()) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }

    [Fact]
    public async Task VerifiedUnsignedMarkerIsTerminalAndNeverQueriesTheUnsignedChild()
    {
        using var fixture = new AuthorityBacktrackingFixture();
        fixture.AlternateReply = reply => reply.Question.Type == 43 ? fixture.Source.Unsigned(reply.Question, reply.Server) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(AuthorityBacktrackingFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.UnsignedDelegation, result.Outcome);
        Assert.Equal(fixture.Source.Child, result.UnsignedDelegation); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }
}
