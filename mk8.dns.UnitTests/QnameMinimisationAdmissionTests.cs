using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class QnameMinimisationAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task InvalidDiscoveryCannotRevealTheOriginalQuestion(int mode)
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.team.example.");
        fixture.Transform = (question, server, reply) => question.Type != 2 ? reply : mode switch
        {
            0 => OnlineDnssecFixture.Copy(reply, authority: reply.Authority.Where(record => record.Type != 46).ToArray()),
            1 => OnlineDnssecFixture.Reply(question, server, [], code: 5),
            2 => OnlineDnssecFixture.Copy(reply, question: question with { Name = DnsName.Parse("other.example.") }),
            _ => OnlineDnssecFixture.Reply(question, server, [], code: 3),
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type == 1);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Name.Equals(DnsName.Parse("private.team.example.")));
    }

    [Theory]
    [InlineData(1, 64, 512)]
    [InlineData(32, 2, 512)]
    [InlineData(32, 64, 1)]
    public async Task SharedStepExchangeAndVerificationBudgetsRefuseWithoutFullQuestionFallback(int steps, int exchanges, int attempts)
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.team.example.");
        var result = await fixture.Resolver(steps, exchanges, attempts).ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type == 1);
    }

    [Fact]
    public async Task AlternateAuthorityCanSupplyValidDiscoveryAfterInvalidReply()
    {
        using var fixture = new QnameMinimisationFixture { AlternateRoot = true }; fixture.AddAddress("private.team.example.");
        fixture.Transform = (question, server, reply) => question.Type == 2 && server.Equals(OnlineDnssecFixture.RootServer)
            ? OnlineDnssecFixture.Copy(reply, authority: reply.Authority.Where(record => record.Type != 46).ToArray()) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Contains(fixture.Calls, call => call.Question.Type == 2 && call.Server.Equals(QnameMinimisationFixture.Alternate));
    }

    [Fact]
    public async Task LegacyConstructorStillUsesTheOriginalQueryAtAncestors()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("secret.child.example.", child: true);
        var resolver = new DnssecIterativeResolver(fixture, DnssecFixture.Verifier, fixture.Source.Anchor(), [OnlineDnssecFixture.RootServer],
            OnlineDnssecFixture.ChildServer.Port, time: fixture.Source.Clock);
        var question = new DnsQuestion(DnsName.Parse("secret.child.example."), 1, 1);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await resolver.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        Assert.Contains(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.RootServer) && call.Question.Equals(question));
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type == 2);
    }

    [Fact]
    public void NullPolicyIsRejectedBeforeAResolverIsCreated()
    {
        using var fixture = new QnameMinimisationFixture();
        Assert.Throws<ArgumentNullException>(() => DnssecIterativeResolver.CreateWithQnameMinimisation(fixture,
            DnssecFixture.Verifier, fixture.Source.Anchor(), [OnlineDnssecFixture.RootServer], null!));
    }
}
