using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientMessageLifetimeTests
{
    [Theory]
    [InlineData(3)]
    [InlineData(4)]
    public async Task ClockMovementAfterInitialProjectionDiscardsAllEncodedBytes(int read)
    {
        using var fixture = new OnlineDnssecFixture();
        var clock = new ClientResponseClock(fixture.Clock);
        var resolver = DnssecIterativeResolver.CreateWithClientProof(fixture, DnssecFixture.Verifier, fixture.Anchor(),
            [OnlineDnssecFixture.RootServer], time: clock);
        var query = ClientMessageFixture.Query();
        var result = await resolver.ResolveDnssecAsync(query.Question!, CancellationToken.None);
        var calls = fixture.Calls.Count;
        clock.Reads = 0;
        clock.BeforeTimestamp = value => { if (value == read) fixture.Clock.Advance(1); };
        Assert.False(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true, authenticatedDataAllowed: true, out var message));
        Assert.Empty(message);
        Assert.Equal(calls, fixture.Calls.Count);
    }

    [Fact]
    public async Task ExpirationAndRollbackCannotTurnHistoricalBytesIntoAuthority()
    {
        using var fixture = new OnlineDnssecFixture();
        var query = ClientMessageFixture.Query();
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(query.Question!, CancellationToken.None);
        Assert.True(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true, authenticatedDataAllowed: true, out var original));
        fixture.Clock.Advance(301);
        Assert.False(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true, authenticatedDataAllowed: true, out var expired));
        Assert.Empty(expired);
        fixture.Clock.SetWall(100);
        Assert.False(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true, authenticatedDataAllowed: true, out var rolledBack));
        Assert.Empty(rolledBack);
        Assert.Contains(ClientMessageFixture.Decode(original, query).Answers, record => record.Ttl == 300);
    }
}
