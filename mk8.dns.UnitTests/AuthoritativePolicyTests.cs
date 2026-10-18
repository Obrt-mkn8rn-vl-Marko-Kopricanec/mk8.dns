using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Contracts;
using Mk8.Dns.Presentation;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class AuthoritativePolicyTests
{
    [Theory]
    [InlineData(0, 1, 50)]
    [InlineData(1, 101, 50)]
    [InlineData(1, 1, 0)]
    public void DirectConstructionCannotDisableTheBounds(int connections, int messages, int milliseconds)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new AuthoritativeListener(new IPEndPoint(IPAddress.Loopback, 5300),
            new Exchange(), connections, messages, TimeSpan.FromMilliseconds(milliseconds)));

    [Fact]
    public async Task OneHeldConnectionRefusesAnotherAndOneMessageClosesTheAdmittedStream()
    {
        var source = new Exchange { Hold = true };
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var endpoint = VacantPair();
        var run = new AuthoritativeListener(endpoint, source, 1, 1, TimeSpan.FromSeconds(2)).RunAsync(caller.Token);
        await TestTaskSettlement.RunAsync(async () =>
        {
            using var first = new TcpClient();
            await first.ConnectAsync(endpoint, guard.Token).ConfigureAwait(true);
            var stream = first.GetStream();
            await using var streamLifetime = stream.ConfigureAwait(true);
            await stream.WriteAsync(new byte[] { 0, 1, 42 }, guard.Token).ConfigureAwait(true);
            await source.Entered.Task.WaitAsync(guard.Token).ConfigureAwait(true);
            using var second = new TcpClient();
            await second.ConnectAsync(endpoint, guard.Token).ConfigureAwait(true);
            var rejected = second.GetStream();
            await using var rejectedLifetime = rejected.ConfigureAwait(true);
            Assert.Equal(0, await SendAndReadCloseAsync(rejected, guard.Token).ConfigureAwait(true));
            Assert.Equal(1, source.Calls);
            Assert.False(run.IsCompleted);
            source.Release.TrySetResult();
            var reply = new byte[3];
            await stream.ReadExactlyAsync(reply, guard.Token).ConfigureAwait(true);
            Assert.Equal(new byte[] { 0, 1, 42 }, reply);
            Assert.Equal(0, await SendAndReadCloseAsync(stream, guard.Token).ConfigureAwait(true));
            Assert.Equal(1, source.Calls);
        }, () => StopAsync(source, caller, run.WaitAsync(CancellationToken.None))).ConfigureAwait(true);
    }

    [Fact]
    public async Task ShorterFrameBudgetClosesAnIncompletePrefixWithoutCallingTheSource()
    {
        var source = new Exchange();
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        var endpoint = VacantPair();
        var run = new AuthoritativeListener(endpoint, source, 1, 1, TimeSpan.FromMilliseconds(50)).RunAsync(caller.Token);
        await TestTaskSettlement.RunAsync(async () =>
        {
            using var client = new TcpClient();
            await client.ConnectAsync(endpoint, guard.Token).ConfigureAwait(true);
            var stream = client.GetStream();
            await using var streamLifetime = stream.ConfigureAwait(true);
            await stream.WriteAsync(new byte[] { 0 }, guard.Token).ConfigureAwait(true);
            Assert.Equal(0, await ReadCloseAsync(stream, guard.Token).ConfigureAwait(true));
            Assert.Equal(0, source.Calls);
            Assert.False(run.IsCompleted);
        }, () => StopAsync(source, caller, run.WaitAsync(CancellationToken.None))).ConfigureAwait(true);
    }

    private static Task StopAsync(Exchange source, CancellationTokenSource caller, Task run)
    {
        source.Release.TrySetResult();
        return TestTaskSettlement.InOrderAsync(caller.CancelAsync, () => TestTaskSettlement.WaitAsync(run.WaitAsync(CancellationToken.None), TimeSpan.FromSeconds(5),
            error => error is OperationCanceledException canceled && canceled.CancellationToken == caller.Token));
    }

    private static async Task<int> ReadCloseAsync(NetworkStream stream, CancellationToken token)
    {
        try { return await stream.ReadAsync(new byte[1], token).ConfigureAwait(true); }
        catch (IOException error) when (error.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset }) { return 0; }
    }

    private static async Task<int> SendAndReadCloseAsync(NetworkStream stream, CancellationToken token)
    {
        try
        {
            await stream.WriteAsync(new byte[] { 0, 1, 43 }, token).ConfigureAwait(true);
            return await ReadCloseAsync(stream, token).ConfigureAwait(true);
        }
        catch (IOException error) when (error.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset }) { return 0; }
    }

    private static IPEndPoint VacantPair()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = Assert.IsType<IPEndPoint>(udp.Client.LocalEndPoint);
        using var tcp = new TcpListener(endpoint); tcp.Start(1);
        return endpoint;
    }

    private sealed class Exchange : IDnsExchange
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);
        internal bool Hold { get; init; }
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken)
        {
            Assert.True(tcp);
            _ = Interlocked.Increment(ref calls);
            Entered.TrySetResult();
            if (Hold) await Release.Task.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            return message.ToArray();
        }
    }
}
