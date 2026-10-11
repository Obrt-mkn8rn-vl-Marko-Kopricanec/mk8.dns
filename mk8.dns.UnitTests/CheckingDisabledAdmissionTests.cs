using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class CheckingDisabledAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task UnsupportedOrDeniedInputsCannotReachEitherSource(int mode)
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        var request = mode switch
        {
            0 => CheckingDisabledFixture.Request(dnssecOk: true),
            1 => CheckingDisabledFixture.Request(flags: 0x0010),
            2 => CheckingDisabledFixture.Request(type: 46),
            3 => new byte[5],
            _ => CheckingDisabledFixture.Request(),
        };
        byte[] peer = mode == 4 ? [198, 51, 100, 1] : ClientRequestFixture.Peer();
        var reply = await f.Processor.ProcessAsync(request, peer, tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(mode == 0 || mode == 2 ? DnssecClientReplyOutcome.Unsupported : mode == 1
            ? DnssecClientReplyOutcome.Refused : mode == 3 ? DnssecClientReplyOutcome.Malformed : DnssecClientReplyOutcome.Denied, reply.Outcome);
        Assert.Null(reply.Revision); Assert.Empty(f.Upstream.Calls); Assert.Empty(f.Epoch.Calls);
        Assert.Equal(0, f.Processor.ActiveRequests); Assert.Equal(0, f.Epoch.Resolver.Statistics.FailureEntries);
    }

    [Fact]
    public async Task DefaultStillRefusesCdAndOptInStillValidatesCdClear()
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        var original = ClientRequestFixture.Processor(f.Epoch); await using var originalLifetime = original.ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Unsupported,
            (await original.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, CancellationToken.None).ConfigureAwait(true)).Outcome);
        var validated = await f.Processor.ProcessAsync(ClientRequestFixture.Request(flags: 0x0120), ClientRequestFixture.Peer(),
            tcp: true, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, validated.Outcome); Assert.Equal(1, validated.Revision);
        Assert.Empty(f.Upstream.Calls); Assert.Equal(2, f.Epoch.Calls.Count); Assert.Equal(1, f.Epoch.Resolver.Statistics.Entries);
    }

    [Fact]
    public async Task FactoryRequiresConcreteSourceClockAndValidRequestBounds()
    {
        var f = new CheckingDisabledFixture(); await using var lifetime = f.ConfigureAwait(true);
        var policy = new DnssecClientAccessPolicy([]);
        // Deliberate null arguments exercise runtime guards despite nullable API contracts.
        Assert.Throws<ArgumentNullException>(() => DnssecClientRequestProcessor.CreateWithCheckingDisabledSource(f.Epoch.Resolver, null!, policy, f.Clock));
        Assert.Throws<ArgumentNullException>(() => DnssecClientRequestProcessor.CreateWithCheckingDisabledSource(f.Epoch.Resolver, f.Unchecked, policy, null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => DnssecClientRequestProcessor.CreateWithCheckingDisabledSource(f.Epoch.Resolver, f.Unchecked, policy, f.Clock, maximumRequests: 0));
        using var canceled = new CancellationTokenSource(); await canceled.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Processor.ProcessAsync(CheckingDisabledFixture.Request(), ClientRequestFixture.Peer(), tcp: true, canceled.Token).AsTask()).ConfigureAwait(true);
        Assert.Empty(f.Upstream.Calls); Assert.Empty(f.Epoch.Calls);
    }
}
