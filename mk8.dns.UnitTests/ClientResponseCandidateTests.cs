using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientResponseCandidateTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CandidateWindowAndReceivedLifetimeAreDistinctBounds(bool shortWindow, bool dnssecOk)
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question();
        fixture.Transform = reply =>
        {
            if (!reply.Question.Equals(question)) return reply;
            var signature = Assert.Single(reply.Answers, record => record.Type == 46);
            var bytes = signature.GetData(); bytes[^1] ^= 1;
            if (shortWindow) BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), 101);
            var candidate = new DnsRecord(signature.Owner, 46, shortWindow ? 300U : 1U, bytes);
            return OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers, candidate]);
        };
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(300U, result.AuthenticatedTtl);
        Assert.Equal(2, result.ClientProof!.AnswerSignatures.Count);
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var snapshot));
        Assert.Equal(shortWindow || dnssecOk ? 1U : 300U, snapshot.RemainingTtl);
        fixture.Clock.Advance(2);
        var canPrepare = DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk, out var later);
        Assert.Equal(!shortWindow && !dnssecOk, canPrepare);
        if (canPrepare) Assert.Equal(298U, Assert.IsType<DnssecClientResponseSnapshot>(later).RemainingTtl);
        else Assert.Null(later);
        // The original candidate material retains its historical received TTL.
        Assert.Equal(shortWindow ? 300U : 1U, result.ClientProof.AnswerSignatures[1].Ttl);
    }

    [Fact]
    public async Task ClockMovementDuringPreparationDiscardsTheEntireProjection()
    {
        using var fixture = new OnlineDnssecFixture();
        var clock = new ClientResponseClock(fixture.Clock);
        var resolver = DnssecIterativeResolver.CreateWithClientProof(fixture, DnssecFixture.Verifier, fixture.Anchor(),
            [OnlineDnssecFixture.RootServer], time: clock);
        var question = ClientProofFixture.Question();
        var result = await resolver.ResolveDnssecAsync(question, CancellationToken.None);
        var calls = fixture.Calls.Count;
        clock.Reads = 0;
        clock.BeforeTimestamp = read => { if (read == 2) fixture.Clock.Advance(1); };
        Assert.False(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk: true, out var snapshot));
        Assert.Null(snapshot);
        Assert.Equal(2, clock.Reads);
        Assert.Equal(calls, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IndependentResultsKeepTheirOwnClockAndExpiryAuthority(bool wallOnly)
    {
        using var firstSource = new OnlineDnssecFixture();
        using var secondSource = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question();
        var first = await ClientProofFixture.Resolver(firstSource).ResolveDnssecAsync(question, CancellationToken.None);
        var second = await ClientProofFixture.Resolver(secondSource).ResolveDnssecAsync(question, CancellationToken.None);
        if (wallOnly) firstSource.Clock.SetWall(401);
        else firstSource.Clock.Advance(301);
        Assert.False(DnssecClientResponseProjection.TryPrepare(first, question, dnssecOk: true, out var expired));
        Assert.Null(expired);
        Assert.True(DnssecClientResponseProjection.TryPrepare(second, question, dnssecOk: true, out var current));
        Assert.Equal(300U, current.RemainingTtl);
        Assert.Equal(2, firstSource.Calls.Count);
        Assert.Equal(2, secondSource.Calls.Count);
    }

    [Fact]
    public async Task ReturnedValuesAreImmutableHistoricalSnapshots()
    {
        using var fixture = new OnlineDnssecFixture();
        var question = ClientProofFixture.Question();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(question, CancellationToken.None);
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk: true, out var first));
        var signature = Assert.Single(first.Answers, record => record.Type == 46);
        var original = signature.GetData(); var modified = signature.GetData(); modified[^1] ^= 1;
        Assert.Equal(original, signature.GetData());
        Assert.Throws<NotSupportedException>(() => ((IList<DnsRecord>)first.Answers).Clear());
        fixture.Clock.Advance(5);
        Assert.True(DnssecClientResponseProjection.TryPrepare(result, question, dnssecOk: true, out var later));
        Assert.Equal(300U, first.RemainingTtl);
        Assert.Equal(295U, later.RemainingTtl);
    }
}
