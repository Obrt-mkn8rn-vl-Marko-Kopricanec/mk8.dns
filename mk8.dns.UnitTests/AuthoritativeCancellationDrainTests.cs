using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Contracts;
using Mk8.Dns.Presentation;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthoritativeCancellationDrainTests
{
    [Fact]
    public async Task CallbackFaultCannotRetireBindingsBeforeHeldAdmittedExchangeSettles()
    {
        using var reservation = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        reservation.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = Assert.IsType<IPEndPoint>(reservation.LocalEndPoint);
        reservation.Dispose();
        var exchange = new HeldExchange();
        await using var exchangeLifetime = exchange.ConfigureAwait(true);
        using var caller = new CancellationTokenSource();
        var run = new AuthoritativeListener(endpoint, exchange).RunAsync(caller.Token);
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await TestTaskSettlement.RunAsync(async () =>
        {
            _ = await udp.SendAsync(new byte[] { 1 }, endpoint, CancellationToken.None).ConfigureAwait(true);
            await exchange.UdpEntered.Task.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(true);
            await tcp.ConnectAsync(endpoint, CancellationToken.None).ConfigureAwait(true);
            await tcp.GetStream().WriteAsync(new byte[] { 0, 1, 1 }, CancellationToken.None).ConfigureAwait(true);
            await exchange.TcpEntered.Task.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(true);
            exchange.TcpRelease.TrySetResult();
            await exchange.TcpFailed.Task.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(true);
            // No unrelated connection or caller stop wakes the accept operation.
            await exchange.CallbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(true);
            Assert.False(run.IsCompleted);
            Assert.False(caller.IsCancellationRequested);
            Assert.Equal(1, exchange.Active);
            exchange.Release.TrySetResult([]);
            var error = await Assert.ThrowsAsync<AggregateException>(() => run.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None)).ConfigureAwait(true);
            Assert.Contains(exchange.Primary, error.Flatten().InnerExceptions);
            Assert.Contains(exchange.CallbackFault, error.Flatten().InnerExceptions);
            Assert.Equal(0, exchange.Active);
            using var binding = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            binding.Bind(endpoint);
        }, async () =>
        {
            exchange.Release.TrySetResult([]); exchange.TcpRelease.TrySetResult();
            await TestTaskSettlement.RunAsync(() => caller.CancelAsync(), async () =>
            {
                var error = await Record.ExceptionAsync(() => run.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None)).ConfigureAwait(true);
                if (error is not null and not AggregateException and not OperationCanceledException)
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
                await exchange.DisposeAsync().ConfigureAwait(true);
            }).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }

    private sealed class HeldExchange : IDnsExchange, IAsyncDisposable
    {
        private CancellationTokenRegistration registration;
        private int active;
        internal int Active => Volatile.Read(ref active);
        internal InvalidOperationException Primary { get; } = new("Owned TCP exchange fault.");
        internal IOException CallbackFault { get; } = new("Owned UDP callback fault.");
        internal TaskCompletionSource UdpEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource TcpEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource TcpRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource TcpFailed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource CallbackEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<byte[]> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken)
        {
            if (tcp)
            {
                TcpEntered.TrySetResult();
                await TcpRelease.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
                await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
                TcpFailed.TrySetResult(); throw Primary;
            }
            Interlocked.Increment(ref active);
            registration = cancellationToken.Register(() => { CallbackEntered.TrySetResult(); throw CallbackFault; });
            UdpEntered.TrySetResult();
            try { return await Release.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true); }
            finally { Interlocked.Decrement(ref active); }
        }
        public ValueTask DisposeAsync() => registration.DisposeAsync();
    }
}
