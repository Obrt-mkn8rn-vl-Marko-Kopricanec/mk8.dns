using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeClientHostAdmissionTests
{
    [Theory]
    [InlineData(0, 2, 2, 2)]
    [InlineData(257, 2, 2, 2)]
    [InlineData(2, 0, 2, 2)]
    [InlineData(2, 17, 2, 2)]
    [InlineData(2, 2, 0, 2)]
    [InlineData(2, 2, 65, 2)]
    [InlineData(2, 2, 2, 0)]
    [InlineData(2, 2, 2, 257)]
    public async Task InvalidBoundsRefuseWithoutAcquisitionOrBorrowedClosure(int requests, int workers, int connections, int messages)
    {
        var f = new ClientProofEpochFixture(); await using var lifetime = f.ConfigureAwait(true);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
        {
            _ = await DnssecClientHost.CreateAsync(f.Refresh, f.Anchors.Upstream, f.Verifier, [AnchorRefreshFixture.Server],
                new DnssecTrustEpochPolicy(), new DnssecClientAccessPolicy([]), new IPEndPoint(IPAddress.Loopback, 0),
                new DnssecWorkPolicy(), f.Timers, maximumRequests: requests, udpWorkers: workers,
                maximumTcpConnections: connections, maximumTcpMessages: messages).ConfigureAwait(true);
        }).ConfigureAwait(true);
        Assert.Equal(0, f.Anchors.Upstream.Calls); Assert.Equal(1, f.Refresh.Current.Revision);
        Assert.Equal(0, f.Timers.ActiveTimers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CopiedBindingServesOneSharedProofCacheAndOneUseRun(bool ipv6)
    {
        var f = new NativeClientHostFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var original = new IPEndPoint(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0);
        var host = await f.CreateAsync(ipv6, original).ConfigureAwait(true);
        original.Port = 1; original.Address = ipv6 ? IPAddress.IPv6Any : IPAddress.Any;
        using var canceled = new CancellationTokenSource(); await canceled.CancelAsync().ConfigureAwait(true);
        Assert.Throws<OperationCanceledException>((Action)(() => _ = host.RunAsync(canceled.Token)));
        var running = host.RunAsync(deadline.Token);
        Assert.Throws<InvalidOperationException>((Action)(() => _ = host.RunAsync(deadline.Token)));
        var endpoint = await host.WaitForBoundAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, endpoint.Address); Assert.NotEqual(1, endpoint.Port);
        var packet = ClientRequestFixture.Request();
        var first = await NativeClientListenerFixture.UdpAsync(endpoint, packet, deadline.Token).ConfigureAwait(true);
        var calls = f.Inputs.Calls.Count; var verifications = f.Inputs.Verifier.Calls;
        using var peer = new TcpClient(endpoint.AddressFamily); await peer.ConnectAsync(endpoint, deadline.Token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        await stream.WriteAsync(TcpSessionFixture.Frame(packet), deadline.Token).ConfigureAwait(true);
        var second = await NativeClientListenerFixture.ReadFrameAsync(stream, deadline.Token).ConfigureAwait(true);
        Assert.Equal(first, second); Assert.Equal(32, System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(first.AsSpan(2)) & 32);
        Assert.Equal(calls, f.Inputs.Calls.Count); Assert.Equal(verifications, f.Inputs.Verifier.Calls);
        Assert.True(DnsMessageCodec.MaximumMessageBytes >= second.Length);
        await host.DisposeAsync().ConfigureAwait(true); await running.ConfigureAwait(true);
        Assert.Equal(0, host.ActiveRequests); Assert.Equal(0, host.ActiveWorkers); Assert.Equal(0, host.ActiveTcpConnections);
    }

    [Fact]
    public async Task PartialBindFailureRetiresOwnedCompositionAndPreservesBorrowers()
    {
        var f = new NativeClientHostFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var occupied = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = Assert.IsType<IPEndPoint>(occupied.Client.LocalEndPoint);
        var host = await f.CreateAsync(endpoint: endpoint).ConfigureAwait(true);
        var running = host.RunAsync(CancellationToken.None);
        var error = await Assert.ThrowsAnyAsync<Exception>(() => running.WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        var leaves = error is AggregateException aggregate ? aggregate.Flatten().InnerExceptions.ToArray() : [error];
        Assert.All(leaves, leaf => Assert.IsType<SocketException>(leaf));
        // The same original socket failure survives each shared disposal.
        f.ExpectedFailure = leaves[0];
        foreach (var closing in new[] { host.DisposeAsync().AsTask(), host.DisposeAsync().AsTask() })
        {
            var failure = await Assert.ThrowsAnyAsync<Exception>(() => closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.True(NativeClientListenerFixture.OnlyExpected(failure, f.ExpectedFailure));
        }
        Assert.Equal(0, host.ActiveWorkers); Assert.Equal(0, host.ActiveRequests); Assert.Empty(f.Inputs.Calls);
        Assert.Equal(1, f.Inputs.Refresh.Current.Revision);
        using var successor = new TcpListener(IPAddress.Loopback, endpoint.Port); successor.Start();
    }
}
