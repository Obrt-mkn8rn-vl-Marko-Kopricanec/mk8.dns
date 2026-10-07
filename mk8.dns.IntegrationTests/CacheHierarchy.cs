using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;

namespace Mk8.Dns.IntegrationTests;

internal sealed class CacheHierarchy : IAsyncDisposable
{
    private readonly UdpClient root;
    private readonly UdpClient child;
    private readonly CancellationTokenSource closure = new(TimeSpan.FromSeconds(20));
    private readonly Task[] workers;
    private int rootRequests;
    private int childRequests;

    internal CacheHierarchy(bool ipv6, Func<DnsQuery, CancellationToken, ValueTask<DnsAnswer>> reply)
    {
        root = Bind(ipv6);
        try { child = Bind(ipv6); }
        catch { root.Dispose(); closure.Dispose(); throw; }
        var rootEndpoint = Endpoint(root);
        var childEndpoint = Endpoint(child);
        var address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        var client = new DnsUpstreamClient(endpoint => new IPAddress(endpoint.GetAddress()).Equals(address)
            && (endpoint.Port == rootEndpoint.Port || endpoint.Port == childEndpoint.Port), TimeSpan.FromSeconds(3));
        Resolver = new NonValidatingIterativeResolver(client, [rootEndpoint], childEndpoint.Port);
        var referral = new DnsAnswer(0, false, [], [new DnsRecord(DnsName.Parse("example."), 2, 5, DnsName.Parse("ns.example.").ToWire())],
            [new DnsRecord(DnsName.Parse("ns.example."), ipv6 ? (ushort)28 : (ushort)1, 5, address.GetAddressBytes())]);
        workers = [RunAsync(root, (_, _) => ValueTask.FromResult(referral), true), RunAsync(child, reply, false)];
    }

    internal IDnsResolver Resolver { get; }
    internal CancellationToken Token => closure.Token;
    internal int RootRequests => Volatile.Read(ref rootRequests);
    internal int ChildRequests => Volatile.Read(ref childRequests);

    public async ValueTask DisposeAsync()
    {
        try
        {
            await closure.CancelAsync().ConfigureAwait(true);
            await Task.WhenAll(workers).ConfigureAwait(true);
        }
        finally
        {
            root.Dispose(); child.Dispose(); closure.Dispose();
        }
    }

    private async Task RunAsync(UdpClient socket, Func<DnsQuery, CancellationToken, ValueTask<DnsAnswer>> reply, bool isRoot)
    {
        try
        {
            while (true)
            {
                var packet = await socket.ReceiveAsync(closure.Token).ConfigureAwait(true);
                if (isRoot) Interlocked.Increment(ref rootRequests); else Interlocked.Increment(ref childRequests);
                var query = DnsMessageCodec.DecodeQuery(packet.Buffer);
                if ((query.Flags & 0x0100) != 0) throw new FormatException("Iteration must not request forwarding.");
                var answer = await reply(query, closure.Token).ConfigureAwait(true);
                await socket.SendAsync(DnsMessageCodec.EncodeResponse(query, answer, true), packet.RemoteEndPoint, closure.Token).ConfigureAwait(true);
            }
        }
        catch (OperationCanceledException) when (closure.IsCancellationRequested)
        {
            // The owner joins this terminal loop before releasing the sockets.
        }
    }

    private static UdpClient Bind(bool ipv6)
    {
        var result = new UdpClient(ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        if (ipv6) result.Client.DualMode = false;
        result.Client.Bind(new IPEndPoint(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0));
        return result;
    }
    private static DnsServerEndpoint Endpoint(UdpClient socket)
    {
        var endpoint = (IPEndPoint)socket.Client.LocalEndPoint!;
        return new DnsServerEndpoint(endpoint.Address.GetAddressBytes(), (ushort)endpoint.Port);
    }
}
