using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofCacheFenceTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(301)]
    public async Task ClockMovementDuringHitCannotRebaseOldMaterial(int seconds)
    {
        using var fixture = new OnlineDnssecFixture();
        var clock = new ClientResponseClock(fixture.Clock);
        var source = DnssecIterativeResolver.CreateWithClientProof(fixture, DnssecFixture.Verifier, fixture.Anchor(),
            [OnlineDnssecFixture.RootServer], time: clock);
        var cache = CachingDnssecResolver.CreateWithClientProofCache(source);
        await using var lifetime = cache.ConfigureAwait(true);
        var question = ClientProofFixture.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var trigger = clock.Reads + 4;
        clock.BeforeTimestamp = read =>
        {
            if (read != trigger) return;
            clock.BeforeTimestamp = null;
            fixture.Clock.Advance(seconds);
        };
        var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Null(clock.BeforeTimestamp);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(300U, result.AuthenticatedTtl);
        Assert.Equal(4, fixture.Calls.Count);
        Assert.Equal(0, cache.Statistics.Hits);
        Assert.Equal(1, cache.Statistics.Expirations);
        var hit = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(300U, hit.AuthenticatedTtl);
        Assert.Equal(4, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedAndUnsignedResultsNeverStoreProofOrFailureState(bool unsignedChild)
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = unsignedChild };
        var question = ClientProofFixture.Question(unsignedChild ? "www.child.example." : "www.example.");
        if (!unsignedChild)
        {
            fixture.Transform = reply => reply.Question.Equals(question)
                ? OnlineDnssecFixture.Copy(reply, answers: []) : reply;
        }
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture));
        await using var lifetime = cache.ConfigureAwait(true);
        for (var index = 0; index < 2; index++)
        {
            var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
            Assert.Equal(unsignedChild ? DnssecResolutionOutcome.UnsignedDelegation : DnssecResolutionOutcome.Failure, result.Outcome);
            Assert.Null(result.ClientProof);
            Assert.Empty(result.Answers);
        }
        Assert.Equal(0, cache.Statistics.Entries);
        Assert.Equal(0, cache.FailureStatistics.Entries);
        Assert.Equal(0, cache.Statistics.Hits);
        Assert.True(fixture.Calls.Count >= 4);
    }

    [Fact]
    public async Task ExactTypeAndClassIdentityCannotJoinAnAuthenticatedAHit()
    {
        using var fixture = new OnlineDnssecFixture();
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture));
        await using var lifetime = cache.ConfigureAwait(true);
        var question = ClientProofFixture.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var foreign = await cache.ResolveDnssecAsync(new DnsQuestion(question.Name, 1, 3), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, foreign.Outcome);
        Assert.Null(foreign.ClientProof);
        var negative = await cache.ResolveDnssecAsync(new DnsQuestion(question.Name, 28, 1), CancellationToken.None);
        Assert.Empty(negative.Answers);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, negative.Outcome);
        Assert.NotNull(negative.ClientProof);
        Assert.Equal(0, cache.Statistics.Hits);
        Assert.Equal(2, cache.Statistics.Entries);
        Assert.Single((await cache.ResolveDnssecAsync(question, CancellationToken.None)).Answers);
    }
}
