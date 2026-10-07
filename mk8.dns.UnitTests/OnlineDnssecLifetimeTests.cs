using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecLifetimeTests
{
    [Fact]
    public async Task NetworkAndProviderDelayAreChargedBeforeKeyAndDataAdmission()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => { fixture.Clock.Advance(5); return reply; };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(290U, result.AuthenticatedTtl);
        Assert.Equal(290U, Assert.Single(result.Answers).Ttl);
    }

    [Fact]
    public async Task ZeroLifetimeDnskeyCannotBootstrap()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Select(record => record.WithTtl(0)).ToArray());
        var result = await fixture.Resolver().ResolveDnssecAsync(Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Single(fixture.Calls);
    }

    [Fact]
    public async Task ParentLeaseExpiryDuringChildKeyWorkCannotAuthorizeChildData()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type == 48 && reply.Question.Name.Equals(fixture.Child)) fixture.Clock.Advance(301);
            return reply;
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question("www.child.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer) && call.Question.Type == 1);
    }

    [Fact]
    public async Task EarlierAliasWindowIsRecheckedAfterTargetNetworkWork()
    {
        using var fixture = Alias();
        fixture.Transform = reply =>
        {
            if (reply.Question.Name.Equals(DnsName.Parse("alias.example.")))
                return ShortAlias(fixture, reply, 101);
            if (reply.Question.Name.Equals(DnsName.Parse("www.example."))) fixture.Clock.Advance(2);
            return reply;
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question("alias.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }

    [Fact]
    public async Task LastProviderCannotInvalidateAnEarlierFinalProofWithoutRefusal()
    {
        using var fixture = Alias();
        var calls = 0;
        var verifier = new DnssecChainFixture.CountingVerifier { AfterVerify = () => { if (++calls == 5) fixture.Clock.Advance(4); } };
        fixture.Transform = reply => reply.Question.Name.Equals(DnsName.Parse("alias.example.")) ? ShortAlias(fixture, reply, 103) : reply;
        var result = await fixture.Resolver(verifier: verifier).ResolveDnssecAsync(Question("alias.example."), CancellationToken.None);
        Assert.Equal(5, verifier.Calls);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }

    [Fact]
    public async Task ObservedWallExpiryCannotReviveOnSameResolverAfterRollback()
    {
        using var fixture = new OnlineDnssecFixture();
        var resolver = fixture.Resolver();
        fixture.Clock.SetWall(10_001);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(Question(), CancellationToken.None)).Outcome);
        fixture.Clock.SetWall(100);
        Assert.Equal(DnssecResolutionOutcome.Failure, (await resolver.ResolveDnssecAsync(Question(), CancellationToken.None)).Outcome);
    }

    [Fact]
    public async Task BackwardMonotonicAndWallSamplesDoNotRestoreSpentLifetime()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply =>
        {
            if (reply.Question.Type == 48) fixture.Clock.Advance(10);
            else { fixture.Clock.SetMonotonic(0); fixture.Clock.SetWall(100); }
            return reply;
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(290U, result.AuthenticatedTtl);
    }

    [Fact]
    public async Task CancelledQueryOwnsIgnoringProviderUntilItsActualCompletion()
    {
        using var fixture = new OnlineDnssecFixture();
        using var cancellation = new CancellationTokenSource();
        var completion = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (_, _, _) => new ValueTask<DnsUpstreamEvidence>(completion.Task);
        var operation = fixture.Resolver().ResolveDnssecAsync(Question(), cancellation.Token).AsTask();
        try
        {
            Assert.Single(fixture.Calls);
            await cancellation.CancelAsync();
            Assert.False(operation.IsCompleted);
        }
        finally
        {
            completion.TrySetResult(fixture.Default(new DnsQuestion(fixture.Root, 48, 1), OnlineDnssecFixture.RootServer));
            OperationCanceledException? terminal = null;
            try { await operation.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException error) { terminal = error; }
            Assert.IsAssignableFrom<OperationCanceledException>(terminal);
        }
        Assert.Single(fixture.Calls);
    }

    private static DnsQuestion Question(string name = "www.example.") => new(DnsName.Parse(name), 1, 1);
    private static OnlineDnssecFixture Alias()
    {
        var fixture = new OnlineDnssecFixture();
        fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("alias.example."), 5, 300, DnsName.Parse("www.example.").ToWire()));
        return fixture;
    }
    private static DnsUpstreamEvidence ShortAlias(OnlineDnssecFixture fixture, DnsUpstreamEvidence reply, uint expiration)
    {
        var data = reply.Answers.Where(record => record.Type == 5).ToArray();
        return OnlineDnssecFixture.Copy(reply, answers: [.. data, fixture.Sign(data, window: new DnssecSignatureWindow(100, expiration))]);
    }
}
