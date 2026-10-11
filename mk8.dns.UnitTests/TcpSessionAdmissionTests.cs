using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class TcpSessionAdmissionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DeniedPeerNeverReadsOrWritesEvenMalformedFraming(bool mapped)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var stream = new TcpSessionStream([0]); await using var streamLifetime = stream.ConfigureAwait(true);
        var peer = mapped ? Convert.FromHexString("00000000000000000000FFFFC0000201") : [198, 51, 100, 1];
        var session = new DnssecClientTcpSession(processor, stream, peer); await using var sessionLifetime = session.ConfigureAwait(true);
        var result = await session.RunAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientTcpSessionOutcome.Denied, result.Outcome); Assert.Equal(0, result.MessagesRead); Assert.Equal(0, result.RepliesWritten);
        Assert.Equal(0, stream.ReadCalls); Assert.Equal(0, stream.WriteCalls); Assert.Empty(f.Calls); Assert.Equal(0, stream.DisposeCalls);
    }

    [Fact]
    public async Task ConstructorAndPreCanceledOrClosedAdmissionDoNotTouchBorrowedResources()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = CompleteTcpFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        var legacy = ClientRequestFixture.Processor(f); await using var legacyLifetime = legacy.ConfigureAwait(true);
        var stream = new TcpSessionStream([]); await using var streamLifetime = stream.ConfigureAwait(true);
        Assert.Throws<ArgumentException>(() => new DnssecClientTcpSession(legacy, stream, ClientRequestFixture.Peer()));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer(), 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer(), 257));
        Assert.Throws<ArgumentException>(() => new DnssecClientTcpSession(processor, stream, new byte[3]));
        var session = new DnssecClientTcpSession(processor, stream, ClientRequestFixture.Peer()); await using var sessionLifetime = session.ConfigureAwait(true);
        using var caller = new CancellationTokenSource(); await caller.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => session.RunAsync(caller.Token).AsTask()).ConfigureAwait(true);
        await session.DisposeAsync().ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => session.RunAsync(CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, stream.ReadCalls); Assert.Equal(0, stream.WriteCalls); Assert.Equal(0, stream.DisposeCalls); Assert.Empty(f.Calls);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, (await processor.ProcessAsync(ClientRequestFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true)).Outcome);
    }
}
