using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientResponseLifetimeTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task QueuedAgeSpendsBothClocksAndNeverRevives(bool wallOnly, bool dnssecOk)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        if (wallOnly) fixture.Clock.SetWall(105);
        else fixture.Clock.Advance(5);
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var aged));
        Assert.Equal(295U, aged.RemainingTtl);
        fixture.Clock.SetWall(100); fixture.Clock.SetMonotonic(0);
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var backward));
        Assert.Equal(295U, backward.RemainingTtl);
        fixture.Clock.SetWall(401);
        Assert.False(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var expired));
        Assert.Null(expired);
        fixture.Clock.SetWall(100); fixture.Clock.SetMonotonic(0);
        Assert.False(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var revived));
        Assert.Null(revived);
        Assert.Equal(300U, result.AuthenticatedTtl);
        Assert.Equal(300U, Assert.Single(result.ClientProof!.AnswerSignatures).Ttl);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ZeroTtlAuthenticationDoesNotCreateReusableProjection(bool dnssecOk)
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => reply.Question.Type == 48 ? reply
            : OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers.Select(record => record.WithTtl(0))]);
        var question = ClientProofFixture.Question();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(0U, result.AuthenticatedTtl);
        Assert.False(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var snapshot));
        Assert.Null(snapshot);
    }
}
