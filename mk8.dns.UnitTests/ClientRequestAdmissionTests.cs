using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientRequestAdmissionTests
{
    [Theory]
    [InlineData("www.example.", 1, 1, 0, 0, 5)]
    [InlineData("www.foreign.", 1, 1, 256, 0, 5)]
    [InlineData("www.example.", 1, 3, 256, 0, 4)]
    [InlineData("www.example.", 0, 1, 256, 0, 4)]
    [InlineData("www.example.", 46, 1, 256, 0, 4)]
    [InlineData("www.example.", 252, 1, 256, 0, 4)]
    [InlineData("*.example.", 1, 1, 256, 0, 4)]
    [InlineData("www.example.", 1, 1, 272, 0, 4)]
    [InlineData("www.example.", 1, 1, 256, 1, 16)]
    [InlineData("www.example.", 1, 1, 1280, 0, 1)]
    public async Task UnsupportedOrRefusedRequestsNeverAcquireOrValidate(string name, ushort type, ushort dnsClass,
        ushort flags, byte version, ushort code)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f, ad: true); await using var processorLifetime = processor.ConfigureAwait(true);
        var request = ClientRequestFixture.Request(name, type, flags, dnsClass: dnsClass, version: version);
        var reply = await processor.ProcessAsync(request, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
        ClientRequestFixture.AssertError(request, reply.GetMessage(), code);
        Assert.Null(reply.Revision);
        Assert.Empty(f.Calls); Assert.Equal(0, f.Verifier.Calls); Assert.Equal(0, f.Anchors.Store.Commits);
        Assert.Equal(0, f.Resolver.Statistics.Entries); Assert.Equal(0, f.Resolver.Statistics.FailureEntries);
    }

    [Fact]
    public async Task UnauthorizedPeersReceiveNoReflectionAndDoNoWork()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        foreach (var peer in new byte[][] { [198, 51, 100, 1], [], [1, 2, 3], Convert.FromHexString("00000000000000000000FFFFC0000201") })
        {
            var result = await processor.ProcessAsync(ClientRequestFixture.Request(), peer, tcp: true, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecClientReplyOutcome.Denied, result.Outcome); Assert.Empty(result.GetMessage());
        }
        Assert.Empty(f.Calls); Assert.Equal(0, processor.ActiveRequests);
    }

    [Fact]
    public async Task ShortUnsolicitedAndOversizedInputsCannotCauseAcquisition()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        foreach (var input in new byte[][] { [], new byte[11], new byte[65536], ClientRequestFixture.Request(flags: 0x8100) })
        {
            var reply = await processor.ProcessAsync(input, ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true);
            Assert.Equal(DnssecClientReplyOutcome.Malformed, reply.Outcome); Assert.Empty(reply.GetMessage());
        }
        Assert.Empty(f.Calls); Assert.Equal(0, processor.ActiveRequests);
    }

    [Fact]
    public async Task NonProofSourceAndInvalidRequestLimitsCannotAdmitWork()
    {
        var f = new TrustEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var policy = new DnssecClientAccessPolicy([]);
        Assert.Throws<ArgumentException>(() => new DnssecClientRequestProcessor(f.Create(), policy));
        Assert.Empty(f.Calls);
        var proofs = new ClientProofEpochFixture(); await using var proofsLifetime = proofs.ConfigureAwait(true);
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecClientRequestProcessor(proofs.Resolver, policy, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecClientRequestProcessor(proofs.Resolver, policy, 257));
        Assert.Empty(proofs.Calls);
    }

    [Fact]
    public async Task ClosingAndPreCanceledAdmissionPreserveTheBorrowedResolver()
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        var processor = ClientRequestFixture.Processor(f); await using var processorLifetime = processor.ConfigureAwait(true);
        using var caller = new CancellationTokenSource(); await caller.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => processor.ProcessAsync(ClientRequestFixture.Request(),
            ClientRequestFixture.Peer(), tcp: true, caller.Token).AsTask()).ConfigureAwait(true);
        var closing = processor.DisposeAsync().AsTask(); Assert.Same(closing, processor.DisposeAsync().AsTask());
        await closing.ConfigureAwait(true);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => processor.ProcessAsync(ClientRequestFixture.Request(),
            ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Empty(f.Calls);
        Assert.NotNull((await f.Resolver.ResolveDnssecAsync(f.Question, CancellationToken.None).ConfigureAwait(true)).ClientProof);
    }
}
