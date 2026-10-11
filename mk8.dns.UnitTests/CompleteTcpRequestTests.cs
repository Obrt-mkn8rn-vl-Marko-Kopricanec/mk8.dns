using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CompleteTcpRequestTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task OversizedTcpRefusalDoesNotPoisonSourceCacheOrUdpTruncation(bool coalesced, bool dnssecOk)
    {
        var f = new ClientProofEpochFixture(coalesced); await using var lifetime = f.ConfigureAwait(true);
        CompleteTcpFixture.Install(f, 260);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var request = ClientRequestFixture.Request(type: 16, dnssecOk: dnssecOk); var query = DnsMessageCodec.DecodeQuery(request);
        var first = await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        ClientRequestFixture.AssertError(request, first.GetMessage(), 2);
        Assert.Equal(DnssecClientReplyOutcome.Failure, first.Outcome); Assert.Null(first.Revision);
        var crypto = f.Verifier.Calls; f.Advance(3);
        var second = await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(first.GetMessage(), second.GetMessage()); Assert.Equal(DnssecClientReplyOutcome.Failure, second.Outcome);
        var udp = await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: false, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, udp.Outcome); Assert.Equal(1, udp.Revision);
        Assert.Equal(0x0200, ClientMessageFixture.Flags(udp.GetMessage()) & 0x0220);
        Assert.Equal(new byte[4], udp.GetMessage().AsSpan(6, 4).ToArray());
        Assert.True(UpstreamMessageCodec.DecodeDnssecResponse(udp.GetMessage(), query.Id, CompleteTcpFixture.Question, OnlineDnssecFixture.RootServer).Truncated);
        Assert.Equal(2, f.Calls.Count); Assert.Equal(crypto, f.Verifier.Calls);
        Assert.Equal(1, f.Resolver.Statistics.Entries); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
        Assert.Equal(0, processor.ActiveRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UdpRetryUsesWholeCachedTcpAnswerThenReacquiresAfterAcknowledgement(bool coalesced)
    {
        var f = new ClientProofEpochFixture(coalesced); await using var lifetime = f.ConfigureAwait(true);
        CompleteTcpFixture.Install(f, 100);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var request = ClientRequestFixture.Request(type: 16); var query = DnsMessageCodec.DecodeQuery(request);
        var udp = await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: false, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0x0200, ClientMessageFixture.Flags(udp.GetMessage()) & 0x0220);
        var crypto = f.Verifier.Calls; f.Advance(3);
        var tcp = await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        var reply = ClientMessageFixture.Decode(tcp.GetMessage(), query);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, tcp.Outcome); Assert.Equal(1, tcp.Revision);
        Assert.Equal(101, reply.Answers.Count); Assert.Equal(0x0020, reply.Flags & 0x0220);
        Assert.All(reply.Answers, record => Assert.Equal(297U, record.Ttl));
        Assert.Equal(2, f.Calls.Count); Assert.Equal(crypto, f.Verifier.Calls);
        Assert.Equal(DnssecAnchorRefreshOutcome.Applied, await f.Refresh.RefreshAsync(CancellationToken.None).ConfigureAwait(true));
        var current = await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, current.Revision); Assert.Equal(DnssecClientReplyOutcome.Encoded, current.Outcome);
        Assert.Equal(4, f.Calls.Count); Assert.Equal(1, f.Anchors.Store.Commits); Assert.Equal(0, processor.ActiveRequests);
    }

    [Fact]
    public async Task CompleteTcpFactoryRetainsProofRequirementQuotaValidationAndDeniedPeerRefusal()
    {
        var legacy = new TrustEpochFixture(); await using var legacyLifetime = legacy.ConfigureAwait(true);
        Assert.Throws<ArgumentException>(() => DnssecClientRequestProcessor.CreateWithCompleteTcpAnswers(legacy.Create(), new DnssecClientAccessPolicy([])));
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        Assert.Throws<ArgumentOutOfRangeException>(() => CompleteTcpFixture.Processor(f, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => CompleteTcpFixture.Processor(f, 257));
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var denied = await processor.ProcessAsync(ClientRequestFixture.Request(), new byte[] { 198, 51, 100, 1 }, tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Denied, denied.Outcome); Assert.Empty(denied.GetMessage());
        Assert.Empty(f.Calls); Assert.Equal(0, f.Verifier.Calls); Assert.Equal(0, processor.ActiveRequests);
    }
}
