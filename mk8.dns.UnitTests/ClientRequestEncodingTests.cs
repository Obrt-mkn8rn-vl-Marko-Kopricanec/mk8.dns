using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientRequestEncodingTests
{
    [Theory]
    [InlineData(false, false, false, false)]
    [InlineData(false, true, false, false)]
    [InlineData(false, false, true, true)]
    [InlineData(false, true, true, true)]
    [InlineData(true, false, false, false)]
    [InlineData(true, true, false, false)]
    [InlineData(true, false, true, true)]
    [InlineData(true, true, true, true)]
    public async Task AuthorizedPacketsRetainProofSelectionIdentityFlagsAndCacheLifetime(bool coalesced, bool dnssecOk, bool adPolicy, bool adQuery)
    {
        var f = new ClientProofEpochFixture(coalesced); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f, adPolicy); await using var processorLifetime = processor.ConfigureAwait(true);
        var packet = ClientRequestFixture.Request(name: "WWW.Example.", flags: adQuery ? (ushort)0x0120 : (ushort)0x0100, dnssecOk: dnssecOk);
        var query = DnsMessageCodec.DecodeQuery(packet);
        var first = await processor.ProcessAsync(packet, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, first.Outcome); Assert.Equal(1, first.Revision);
        var firstMessage = first.GetMessage(); var decoded = ClientMessageFixture.Decode(firstMessage, query);
        Assert.Equal(adPolicy && (dnssecOk || adQuery), (decoded.Flags & 32) != 0);
        Assert.Equal(0x8180, decoded.Flags & 0xffdf); Assert.Equal(dnssecOk ? 2 : 1, decoded.Answers.Count);
        firstMessage[2] = 0; Assert.Equal(0x81, first.GetMessage()[2]);
        f.Advance(3); var crypto = f.Verifier.Calls;
        var hit = await processor.ProcessAsync(packet, ClientRequestFixture.Peer(), tcp: false, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, hit.Outcome);
        Assert.All(ClientMessageFixture.Decode(hit.GetMessage(), query).Answers, record => Assert.Equal(297U, record.Ttl));
        Assert.Equal(2, f.Calls.Count); Assert.Equal(crypto, f.Verifier.Calls); Assert.Equal(0, processor.ActiveRequests);
    }

    [Fact]
    public async Task CallerPacketMutationAfterAdmissionCannotChangeTheOwnedQuestion()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var packet = ClientRequestFixture.Request();
        var pending = processor.ProcessAsync(packet, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).AsTask();
        Array.Clear(packet);
        var reply = await pending.ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, reply.Outcome);
        Assert.All(f.Calls.Where(question => question.Type != 48), question => Assert.Equal(f.Question, question));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExpiredOrFailedMaterialIsEmptyServfailWithoutSecurityStatePromotion(bool failed)
    {
        var f = new ClientProofEpochFixture { DataTtl = failed ? 300U : 0 }; await using var lifetime = f.ConfigureAwait(true);
        if (failed) f.Override = (_, _, _) => throw new IOException("Controlled acquisition failure.");
        var processor = ClientRequestFixture.Processor(f, ad: true); await using var processorLifetime = processor.ConfigureAwait(true);
        var packet = ClientRequestFixture.Request(); var query = DnsMessageCodec.DecodeQuery(packet);
        for (var index = 0; index < 2; index++)
        {
            var reply = await processor.ProcessAsync(packet, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecClientReplyOutcome.Failure, reply.Outcome); Assert.Null(reply.Revision);
            var decoded = ClientMessageFixture.Decode(reply.GetMessage(), query);
            Assert.Equal(2, decoded.ResponseCode); Assert.Equal(0, decoded.Flags & 0x0030);
            Assert.Empty(decoded.Answers); Assert.Empty(decoded.Authority); Assert.Empty(decoded.Additional);
        }
        Assert.Equal(0, f.Resolver.Statistics.Entries); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
    }
}
