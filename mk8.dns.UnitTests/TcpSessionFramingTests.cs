using System.Buffers.Binary;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TcpSessionFramingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FragmentedPipelinedFramesPreserveIdsProofSelectionAndOneSourceCache(bool coalesced)
    {
        var f = new ClientProofEpochFixture(coalesced); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var first = ClientRequestFixture.Request(); var second = ClientRequestFixture.Request(dnssecOk: false);
        BinaryPrimitives.WriteUInt16BigEndian(second, 902);
        var stream = new TcpSessionStream([.. TcpSessionFixture.Frame(first), .. TcpSessionFixture.Frame(second)]); await using var streamLifetime = stream.ConfigureAwait(true);
        var peer = ClientRequestFixture.Peer(); var session = new DnssecClientTcpSession(processor, stream, peer);
        await using var sessionLifetime = session.ConfigureAwait(true); Array.Clear(peer);
        var result = await session.RunAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientTcpSessionOutcome.EndOfStream, result.Outcome);
        Assert.Equal(2, result.MessagesRead); Assert.Equal(2, result.RepliesWritten); Assert.Equal(2, stream.FlushCalls);
        var replies = TcpSessionFixture.Replies(stream); Assert.Equal(2, replies.Length);
        var proof = ClientMessageFixture.Decode(replies[0], DnsMessageCodec.DecodeQuery(first));
        var plain = ClientMessageFixture.Decode(replies[1], DnsMessageCodec.DecodeQuery(second));
        Assert.Equal(2, proof.Answers.Count); Assert.Single(plain.Answers); Assert.Equal(0x0020, proof.Flags & 0x0220);
        Assert.Equal(0, plain.Flags & 0x0220); Assert.Equal(2, f.Calls.Count); Assert.Equal(0, processor.ActiveRequests);
        Assert.Equal(0, stream.DisposeCalls); Assert.True(stream.CanRead);
    }

    [Fact]
    public async Task MessageLimitLeavesNextCompleteFrameUnreadAndStreamBorrowed()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var frame = TcpSessionFixture.Frame(ClientRequestFixture.Request());
        var stream = new TcpSessionStream([.. frame, .. frame]); await using var streamLifetime = stream.ConfigureAwait(true);
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer(), 1);
        await using var sessionLifetime = session.ConfigureAwait(true);
        var result = await session.RunAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientTcpSessionOutcome.MessageLimit, result.Outcome);
        Assert.Equal(1, result.MessagesRead); Assert.Equal(1, result.RepliesWritten); Assert.Equal(frame.Length, stream.BytesRead);
        Assert.Equal(2, f.Calls.Count); Assert.Single(TcpSessionFixture.Replies(stream)); Assert.Equal(0, stream.DisposeCalls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task PartialPrefixPayloadAndShortDeclaredFramesFaultWithoutSourceWork(int kind)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        byte[] bytes = kind switch { 0 => [0], 1 => [0, 12, 1, 2], 2 => [0, 0], _ => [0, 11] };
        var stream = new TcpSessionStream(bytes); await using var streamLifetime = stream.ConfigureAwait(true);
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer());
        var errorType = kind < 2 ? typeof(EndOfStreamException) : typeof(InvalidDataException);
        try
        {
            var running = session.RunAsync(CancellationToken.None).AsTask();
            await Assert.ThrowsAsync(errorType, async () => await running.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).ConfigureAwait(true);
            Assert.Same(running, session.DisposeAsync().AsTask());
            Assert.Empty(stream.Output); Assert.Empty(f.Calls); Assert.Equal(0, f.Verifier.Calls); Assert.Equal(0, processor.ActiveRequests);
        }
        finally { await TcpSessionFixture.SettleAsync(session, errorType).ConfigureAwait(true); }
    }
}
