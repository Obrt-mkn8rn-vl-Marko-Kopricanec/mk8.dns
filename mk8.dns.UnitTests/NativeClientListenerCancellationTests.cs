using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NativeClientListenerCancellationTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task UnsolicitedBorrowedCancellationCannotBecomeSuccessfulTeardown(bool tcp, bool clock)
    {
        var f = new NativeClientListenerFixture(); await using var lifetime = f.ConfigureAwait(true);
        using var deadline = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        var bound = await f.StartAsync(deadline.Token).ConfigureAwait(true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var fault = new OperationCanceledException("Controlled unsolicited borrowed cancellation.", deadline.Token);
        f.ExpectedFailure = fault;
        if (clock)
        {
            f.Epoch.Clock.BeforeTimestamp = _ =>
            {
                Assert.False(deadline.IsCancellationRequested);
                entered.TrySetResult(); throw fault;
            };
        }
        else
        {
            f.Epoch.Override = (_, _, token) =>
            {
                // Same listener token, still not canceled: equality alone cannot
                // make this unsolicited provider outcome expected cancellation.
                Assert.False(token.IsCancellationRequested);
                fault = new OperationCanceledException("Controlled unsolicited borrowed cancellation.", token);
                f.ExpectedFailure = fault;
                entered.TrySetResult(); return ValueTask.FromException<DnsUpstreamEvidence>(fault);
            };
        }
        try
        {
            Assert.NotNull(f.Running); Assert.False(f.Running.IsCompleted);
            await SendAsync(bound, tcp, deadline.Token).ConfigureAwait(true);
            await entered.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            var failure = await Assert.ThrowsAnyAsync<Exception>(() => f.Running.WaitAsync(AnchorRefreshFixture.Timeout,
                TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            Assert.True(NativeClientListenerFixture.OnlyExpected(failure, fault));
            Assert.False(f.Running.IsCompletedSuccessfully);
            var first = f.Listener.DisposeAsync().AsTask(); var repeated = f.Listener.DisposeAsync().AsTask();
            foreach (var closing in new[] { first, repeated })
            {
                var outcome = await Assert.ThrowsAnyAsync<Exception>(() => closing.WaitAsync(AnchorRefreshFixture.Timeout,
                    TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
                Assert.True(NativeClientListenerFixture.OnlyExpected(outcome, fault));
                Assert.False(closing.IsCompletedSuccessfully);
            }
            f.Epoch.Clock.BeforeTimestamp = null;
            Assert.Equal(0, f.Listener.ActiveTcpConnections); Assert.Equal(0, f.Processor.ActiveRequests);
            Assert.Equal(0, f.Epoch.Resolver.Statistics.ActiveRequests); Assert.Equal(0, f.Epoch.Resolver.ActiveWorkers);
            Assert.False(deadline.IsCancellationRequested);
        }
        finally { f.Epoch.Clock.BeforeTimestamp = null; }
    }

    private static async Task SendAsync(IPEndPoint endpoint, bool tcp, CancellationToken token)
    {
        var packet = ClientRequestFixture.Request();
        if (!tcp)
        {
            using var peer = new UdpClient(endpoint.AddressFamily); peer.Connect(endpoint);
            _ = await peer.SendAsync(packet, token).ConfigureAwait(true); return;
        }
        using var connection = new TcpClient(endpoint.AddressFamily); await connection.ConnectAsync(endpoint, token).ConfigureAwait(true);
        var stream = connection.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        await stream.WriteAsync(TcpSessionFixture.Frame(packet), token).ConfigureAwait(true);
        try { _ = await stream.ReadAsync(new byte[1], token).ConfigureAwait(true); }
        catch (IOException) { }
    }
}
