using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class QnameMinimisationLifetimeTests
{
    [Fact]
    public async Task FirstDiscoverySignatureCapsOutputWithoutAddingInfrastructureRecords()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.team.example.");
        fixture.Transform = (question, server, reply) =>
        {
            if (question.Type != 2 || !question.Name.Equals(DnsName.Parse("team.example."))) return reply;
            var rows = reply.Authority.Where(record => record.Type != 46).ToArray();
            return OnlineDnssecFixture.Copy(reply, authority: [.. rows, .. rows.Select(record => fixture.Source.Sign([record], window: new DnssecSignatureWindow(99, 103)))]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.InRange(Assert.Single(result.Answers).Ttl, 0u, 3u); Assert.InRange(result.AuthenticatedTtl, 0u, 3u);
        Assert.Empty(result.Authority);
    }

    [Fact]
    public async Task DiscoveryExpiryDuringLaterProviderWorkRefusesAllOutput()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.team.example.");
        fixture.Transform = (question, server, reply) =>
        {
            if (question.Type == 2)
            {
                var rows = reply.Authority.Where(record => record.Type != 46).ToArray();
                return OnlineDnssecFixture.Copy(reply, authority: [.. rows, .. rows.Select(record => fixture.Source.Sign([record], window: new DnssecSignatureWindow(99, 103)))]);
            }
            if (question.Type == 1) fixture.Source.Clock.Advance(4);
            return reply;
        };
        var resolver = fixture.Resolver(); var question = new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
    }

    [Fact]
    public async Task ExpiredDiscoveryWindowCannotReviveAfterAWallClockRollback()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.team.example.");
        fixture.Transform = (question, server, reply) =>
        {
            if (question.Type == 2)
            {
                var rows = reply.Authority.Where(record => record.Type != 46).ToArray();
                return OnlineDnssecFixture.Copy(reply, authority: [.. rows, .. rows.Select(record => fixture.Source.Sign([record], window: new DnssecSignatureWindow(99, 103)))]);
            }
            if (question.Type == 1) fixture.Source.Clock.SetWall(104);
            return reply;
        };
        var resolver = fixture.Resolver(); var question = new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        fixture.Source.Clock.SetWall(100);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(question, CancellationToken.None)).Outcome);
        Assert.Equal(1, fixture.Calls.Count(call => call.Question.Type == 1));
    }

    [Fact]
    public async Task CancellationIgnoringDiscoveryRemainsOwnedUntilProviderCompletes()
    {
        using var fixture = new QnameMinimisationFixture();
        var release = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Delayed = (question, token) => new ValueTask<DnsUpstreamEvidence>(release.Task);
        using var cancellation = new CancellationTokenSource();
        var pending = fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1), cancellation.Token).AsTask();
        try
        {
            Assert.Contains(fixture.Calls, call => call.Question.Type == 2);
            await cancellation.CancelAsync().ConfigureAwait(true); Assert.False(pending.IsCompleted);
        }
        finally { release.TrySetResult(null!); }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(5))).ConfigureAwait(true);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type == 1);
    }
}
