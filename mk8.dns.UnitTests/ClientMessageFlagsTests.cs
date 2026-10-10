using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientMessageFlagsTests
{
    [Theory]
    [InlineData(0x0100, false, false, false)]
    [InlineData(0x0100, true, false, false)]
    [InlineData(0x0120, false, true, true)]
    [InlineData(0x0100, false, true, false)]
    [InlineData(0x0100, true, true, true)]
    [InlineData(0x0110, true, true, false)]
    [InlineData(0x0130, false, true, false)]
    [InlineData(0x0000, true, true, true)]
    public async Task ClientBitsNeverSubstituteForLocalAdPolicy(int requestFlags, bool dnssecOk, bool allowAd, bool expectedAd)
    {
        using var fixture = new OnlineDnssecFixture();
        var query = ClientMessageFixture.Query(flags: (ushort)requestFlags, dnssecOk: dnssecOk);
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(query.Question!, CancellationToken.None);
        var calls = fixture.Calls.Count;
        Assert.True(DnssecClientMessageCodec.TryEncode(query, result, tcp: true, recursionAvailable: true, allowAd, out var message));
        var flags = ClientMessageFixture.Flags(message);
        Assert.Equal(requestFlags & 0x0110, flags & 0x0110);
        Assert.Equal(expectedAd, (flags & 0x0020) != 0);
        Assert.Equal(0x8080, flags & 0x84c0);
        var decoded = ClientMessageFixture.Decode(message, query);
        Assert.Equal(dnssecOk, (decoded.EdnsFlags & 0x8000) != 0);
        Assert.Equal(dnssecOk, decoded.Answers.Any(record => record.Type == 46));
        Assert.Empty(decoded.Authority);
        Assert.Empty(decoded.Additional);
        Assert.Equal(calls, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RaIsExplicitAndOriginalQuestionCaseAndIdArePreserved(bool recursionAvailable)
    {
        using var fixture = new OnlineDnssecFixture();
        var query = ClientMessageFixture.Query("WwW.ExAmPlE.", dnssecOk: false, size: null);
        var result = await ClientProofFixture.Resolver(fixture).ResolveDnssecAsync(query.Question!, CancellationToken.None);
        Assert.True(DnssecClientMessageCodec.TryEncode(query, result, tcp: false, recursionAvailable, authenticatedDataAllowed: true, out var message));
        Assert.Equal(recursionAvailable, (ClientMessageFixture.Flags(message) & 0x0080) != 0);
        Assert.Equal(0, ClientMessageFixture.Flags(message) & 0x0020);
        Assert.Equal(query.GetQuestionNameWire(), message.AsSpan(12, query.GetQuestionNameWire().Length).ToArray());
        var decoded = ClientMessageFixture.Decode(message, query);
        Assert.Equal(query.Id, decoded.Id);
        Assert.False(decoded.HasEdns);
    }
}
