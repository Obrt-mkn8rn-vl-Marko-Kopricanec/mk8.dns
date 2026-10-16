using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class NativeClientListenerFixture : IAsyncDisposable
{
    private readonly List<(TaskCompletionSource<DnsUpstreamEvidence> Held, DnsUpstreamEvidence Reply)> held = [];
    internal NativeClientListenerFixture(bool ipv6 = false, bool allowed = true, int connections = 2,
        int messages = 16, bool coalesced = false, IPEndPoint? binding = null)
    {
        Address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        Epoch = new ClientProofEpochFixture(coalesced: coalesced);
        var bytes = Address.GetAddressBytes();
        Processor = DnssecClientRequestProcessor.CreateWithCompleteTcpAnswers(Epoch.Resolver,
            new DnssecClientAccessPolicy(allowed ? [new DnssecClientNetwork(bytes, bytes.Length * 8)] : [], authenticatedDataAllowed: true));
        Listener = new DnssecClientListener(Processor, binding ?? new IPEndPoint(Address, 0), udpWorkers: 2,
            maximumTcpConnections: connections, maximumTcpMessages: messages);
    }
    internal ClientProofEpochFixture Epoch { get; }
    internal IPAddress Address { get; }
    internal DnssecClientRequestProcessor Processor { get; }
    internal DnssecClientListener Listener { get; }
    internal Exception? ExpectedFailure { get; set; }
    internal Task? Running { get; private set; }
    internal async Task<IPEndPoint> StartAsync(CancellationToken token)
    {
        Running = Listener.RunAsync(token);
        return await Listener.WaitForBoundAsync(token).WaitAsync(AnchorRefreshFixture.Timeout,
            TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
    }
    internal TaskCompletionSource<DnsUpstreamEvidence> Hold(DnsQuestion question)
    {
        var pending = Epoch.Hold(question); held.Add((pending, Epoch.Default(question, AnchorRefreshFixture.Server))); return pending;
    }
    internal static bool OnlyExpected(Exception error, Exception? expected)
        => ReferenceEquals(error, expected) || (error is AggregateException aggregate
            && aggregate.Flatten().InnerExceptions.All(item => ReferenceEquals(item, expected)));
    internal static async Task<byte[]> ReadFrameAsync(Stream stream, CancellationToken token)
    {
        var prefix = new byte[2]; await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(true);
        var message = new byte[System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(prefix)];
        await stream.ReadExactlyAsync(message, token).ConfigureAwait(true); return message;
    }
    internal static async Task<byte[]> UdpAsync(IPEndPoint endpoint, byte[] request, CancellationToken token, Action<Socket>? opened = null)
    {
        using var peer = new UdpClient(endpoint.AddressFamily); opened?.Invoke(peer.Client); peer.Connect(endpoint);
        _ = await peer.SendAsync(request, token).ConfigureAwait(true);
        return (await peer.ReceiveAsync(token).ConfigureAwait(true)).Buffer;
    }
    public async ValueTask DisposeAsync()
    {
        var stopped = Listener.DisposeAsync().AsTask();
        foreach (var (Held, Reply) in held) Held.TrySetResult(Reply);
        await TestTaskSettlement.InOrderAsync(
            () => TestTaskSettlement.WaitAsync(stopped.WaitAsync(CancellationToken.None), AnchorRefreshFixture.Timeout,
                error => ExpectedFailure is not null && OnlyExpected(error, ExpectedFailure)),
            async () => await Processor.DisposeAsync().ConfigureAwait(true),
            async () => await Epoch.DisposeAsync().ConfigureAwait(true)).ConfigureAwait(true);
    }
}
