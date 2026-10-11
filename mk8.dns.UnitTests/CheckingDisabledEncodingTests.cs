using System.Buffers.Binary;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CheckingDisabledEncodingTests
{
    [Theory]
    [InlineData(1, false)]
    [InlineData(1, true)]
    [InlineData(28, true)]
    [InlineData(48, true)]
    public async Task OnlyCdSetSelectsUnvalidatedOrdinaryDataWithoutAdRevisionOrCache(int type, bool tcp)
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        var request = CheckingDisabledFixture.Request((ushort)type);
        for (var i = 0; i < 2; i++)
        {
            var reply = await f.Processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, reply.Outcome); Assert.Null(reply.Revision);
            var packet = reply.GetMessage(); Assert.Equal((ushort)0x8190, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2)));
            var parsed = UpstreamMessageCodec.DecodeResponse(packet, 0xabcd, f.Epoch.Question with { Type = (ushort)type });
            Assert.Equal((uint)300, Assert.Single(parsed.Answer.Answers).Ttl); Assert.False(parsed.Answer.Authoritative);
        }
        Assert.Equal(2, f.Upstream.Calls.Count); Assert.Empty(f.Epoch.Calls); Assert.Equal(0, f.Epoch.Verifier.Calls);
        Assert.Equal(0, f.Epoch.Resolver.Statistics.Entries); Assert.Equal(0, f.Epoch.Resolver.Statistics.FailureEntries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AcquisitionChargesForwardWallAndMonotonicTimeIncludingFractionalSeconds(bool wallOnly)
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, _) =>
        {
            if (wallOnly) f.Epoch.Anchors.Keys.Clock.SetWall(103);
            else f.Epoch.Advance(2.1);
            return ValueTask.FromResult(f.Answer(question));
        };
        var reply = await f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        var parsed = UpstreamMessageCodec.DecodeResponse(reply.GetMessage(), 0xabcd, f.Epoch.Question);
        Assert.Equal((uint)297, Assert.Single(parsed.Answer.Answers).Ttl);
        Assert.Equal(DnssecClientReplyOutcome.CheckingDisabled, reply.Outcome);
    }

    [Fact]
    public async Task ZeroTtlIsUnvalidatedNonstoredAndClockMovementDuringEncodingDiscardsBytes()
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        f.Ttl = 0;
        var zero = await f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0U, Assert.Single(UpstreamMessageCodec.DecodeResponse(zero.GetMessage(), 0xabcd, f.Epoch.Question).Answer.Answers).Ttl);
        f.Ttl = 300; var start = f.Clock.Reads;
        f.Clock.BeforeTimestamp = read => { if (read == start + 3) f.Epoch.Advance(1); };
        var reduced = await f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Failure, reduced.Outcome);
        ClientRequestFixture.AssertError(CheckingDisabledFixture.Request(), reduced.GetMessage(), 2);
        Assert.Equal(0, f.Epoch.Resolver.Statistics.Entries); Assert.Equal(0, f.Epoch.Resolver.Statistics.FailureEntries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OversizedOrdinaryTcpObeysExplicitCompletenessWithoutPoisoningValidation(bool complete)
    {
        var f = new CheckingDisabledFixture(complete: complete); await using var lifetime = f.ConfigureAwait(true);
        f.Override = (question, _) => ValueTask.FromResult(new DnsAnswer(0, authoritative: true,
            Enumerable.Range(0, 260).Select(i => new DnsRecord(question.Name, 16, 300, [240, (byte)(i >> 8), .. Enumerable.Repeat((byte)i, 239)])), [], []));
        var request = CheckingDisabledFixture.Request(type: 16);
        var reply = await f.Processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(complete ? DnssecClientReplyOutcome.Failure : DnssecClientReplyOutcome.CheckingDisabled, reply.Outcome);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(reply.GetMessage().AsSpan(2));
        Assert.Equal(complete ? 0 : 0x0200, flags & 0x0200); Assert.Equal(0, flags & 0x0020);
        if (complete) ClientRequestFixture.AssertError(request, reply.GetMessage(), 2);
        Assert.Equal(0, f.Epoch.Resolver.Statistics.Entries); Assert.Empty(f.Epoch.Calls);
    }
}
