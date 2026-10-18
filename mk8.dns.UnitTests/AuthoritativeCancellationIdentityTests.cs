using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Contracts;
using Mk8.Dns.Presentation;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthoritativeCancellationIdentityTests
{
    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(5);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallerStopPreservesUnrelatedHeldSourceCancellationAndReleasesBindings(bool unrelated)
    {
        var endpoint = VacantPair();
        var source = new HeldExchange(unrelated);
        using var caller = new CancellationTokenSource();
        using var peer = new UdpClient(AddressFamily.InterNetwork);
        var running = new AuthoritativeListener(endpoint, source).RunAsync(caller.Token);
        await TestTaskSettlement.RunAsync(async () =>
        {
            _ = await peer.SendAsync(new byte[] { 1 }, endpoint, CancellationToken.None).ConfigureAwait(true);
            await source.Entered.Task.WaitAsync(Guard, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await caller.CancelAsync().ConfigureAwait(true);
            Assert.False(running.IsCompleted);
            source.Release.TrySetResult();
            var error = await Record.ExceptionAsync(() => running.WaitAsync(Guard, TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            if (unrelated)
            {
                var failures = Assert.IsType<AggregateException>(error).Flatten().InnerExceptions;
                Assert.Contains(failures, failure => ReferenceEquals(failure, source.Failure));
                Assert.All(failures, failure => Assert.IsType<OperationCanceledException>(failure, exactMatch: false));
            }
            else
            {
                Assert.Equal(caller.Token, Assert.IsType<OperationCanceledException>(error, exactMatch: false).CancellationToken);
            }
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(endpoint);
            using var tcp = new TcpListener(endpoint);
            tcp.Start(1);
        }, async () =>
        {
            source.Release.TrySetResult();
            await TestTaskSettlement.InOrderAsync(caller.CancelAsync, () => TestTaskSettlement.ObserveAsync(
                running.WaitAsync(CancellationToken.None), error => Expected(error, unrelated, source.Failure, caller.Token))).ConfigureAwait(true);
        }).ConfigureAwait(true);
    }

    private static bool Expected(Exception error, bool unrelated, OperationCanceledException source, CancellationToken caller)
        => unrelated ? error is AggregateException aggregate
            && aggregate.Flatten().InnerExceptions.Any(leaf => ReferenceEquals(leaf, source))
            && aggregate.Flatten().InnerExceptions.All(leaf => leaf is OperationCanceledException)
            : error is OperationCanceledException canceled && canceled.CancellationToken == caller;

    private static IPEndPoint VacantPair()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = Assert.IsType<IPEndPoint>(udp.Client.LocalEndPoint);
        using var tcp = new TcpListener(endpoint);
        tcp.Start(1);
        return endpoint;
    }

    private sealed class HeldExchange(bool unrelated) : IDnsExchange
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal OperationCanceledException Failure { get; } = new("Unrelated UDP source cancellation.");
        public async ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken)
        {
            Assert.False(tcp);
            Entered.TrySetResult();
            await Release.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            if (unrelated) throw Failure;
            return [];
        }
    }
}
