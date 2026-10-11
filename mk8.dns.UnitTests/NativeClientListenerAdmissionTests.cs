using System.Net;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeClientListenerAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task InvalidBoundsFailBeforeBinding(int invalid)
    {
        var f = new NativeClientListenerFixture(); await using var lifetime = f.ConfigureAwait(true);
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecClientListener(f.Processor, new IPEndPoint(IPAddress.Loopback, 0),
            udpWorkers: invalid == 0 ? 0 : invalid == 1 ? 17 : 1,
            maximumTcpConnections: invalid == 2 ? 0 : invalid == 3 ? 65 : 1,
            maximumTcpMessages: invalid == 4 ? 0 : invalid == 5 ? 257 : 1));
        Assert.Empty(f.Epoch.Calls); Assert.Equal(0, f.Processor.ActiveRequests);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task WildcardMappedOrMulticastBindIsNotAnExplicitCanonicalAddress(int invalid)
    {
        var f = new NativeClientListenerFixture(); await using var lifetime = f.ConfigureAwait(true);
        var address = invalid == 0 ? IPAddress.Any : invalid == 1 ? IPAddress.IPv6Any
            : invalid == 2 ? IPAddress.Loopback.MapToIPv6() : invalid == 3 ? new IPAddress([224, 0, 0, 1])
            : invalid == 4 ? IPAddress.Broadcast : IPAddress.Parse("ff02::1");
        Assert.Throws<ArgumentException>(() => new DnssecClientListener(f.Processor, new IPEndPoint(address, 0)));
        Assert.Empty(f.Epoch.Calls);
    }

    [Fact]
    public async Task LegacyProcessorIsRejectedAndPreRunCloseJoinsWithoutBorrowedDisposal()
    {
        var f = new NativeClientListenerFixture(); await using var lifetime = f.ConfigureAwait(true);
        var ordinary = ClientRequestFixture.Processor(f.Epoch); await using var ordinaryLifetime = ordinary.ConfigureAwait(true);
        Assert.Throws<ArgumentException>(() => new DnssecClientListener(ordinary, new IPEndPoint(IPAddress.Loopback, 0)));
        await f.Listener.DisposeAsync().ConfigureAwait(true); await f.Listener.DisposeAsync().ConfigureAwait(true);
        Assert.Throws<ObjectDisposedException>((Action)(() => _ = f.Listener.RunAsync(CancellationToken.None)));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Listener.WaitForBoundAsync(CancellationToken.None)).ConfigureAwait(true);
        var answer = await f.Processor.ProcessAsync(ClientRequestFixture.Request(), IPAddress.Loopback.GetAddressBytes(), tcp: false,
            CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecClientReplyOutcome.Encoded, answer.Outcome);
    }
}
