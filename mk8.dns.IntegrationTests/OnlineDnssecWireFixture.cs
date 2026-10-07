using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

internal sealed class OnlineDnssecWireFixture : IDisposable
{
    private readonly EcdsaP256DnssecSigningKey rootKey = EcdsaP256DnssecSigningKey.Create();
    private readonly EcdsaP256DnssecSigningKey childKey = EcdsaP256DnssecSigningKey.Create();
    internal OnlineDnssecWireFixture(bool ipv6, bool unsigned)
    {
        var address = ipv6 ? IPAddress.IPv6Loopback.GetAddressBytes() : IPAddress.Loopback.GetAddressBytes();
        var child = Zone("child.example.", address, [Record("www.child.example.", 1, [192, 0, 2, 43])]);
        var signedChild = NsecZoneSigner.Sign(child, childKey, Verifier, Window);
        var ns = DnsName.Parse("ns.child.example.");
        var delegation = new DnsRecord(DnsName.Parse("child.example."), 2, 300, ns.ToWire());
        var glue = new DnsRecord(ns, ipv6 ? (ushort)28 : (ushort)1, 300, address);
        var alias = Record("alias.example.", 5, DnsName.Parse("www.child.example.").ToWire());
        var root = Zone("example.", address, unsigned ? [delegation, glue, alias] : [delegation, glue, alias, signedChild.ParentDs.WithTtl(300)]);
        var signedRoot = NsecZoneSigner.Sign(root, rootKey, Verifier, Window);
        Root = Catalog(signedRoot);
        Child = unsigned ? new AuthoritativeCatalog([child]) : Catalog(signedChild);
        Anchor = new DnssecTrustAnchor(signedRoot.Dnskey);
    }

    internal AuthoritativeCatalog Root { get; }
    internal AuthoritativeCatalog Child { get; }
    internal DnssecTrustAnchor Anchor { get; }
    internal TimeProvider Clock { get; } = new FixedClock();
    internal static EcdsaP256DnssecVerifier Verifier { get; } = new();
    private static DnssecSignatureWindow Window { get; } = new(99, 10_000);

    private AuthoritativeCatalog Catalog(SignedZone signed)
        => new([new ZoneContents(signed.Source, signed.GetAllRecords().Where(record => record.Type is 46 or 47 or 48))], Verifier, Clock);

    private static AuthoritativeZone Zone(string name, byte[] address, DnsRecord[] records)
    {
        var origin = DnsName.Parse(name);
        var ns = origin.PrependLabel("ns"u8);
        return new AuthoritativeZone(origin, [Soa(origin), new DnsRecord(origin, 2, 300, ns.ToWire()),
            new DnsRecord(ns, address.Length == 4 ? (ushort)1 : (ushort)28, 300, address), .. records]);
    }

    private static DnsRecord Soa(DnsName origin)
    {
        var ns = origin.PrependLabel("ns"u8).ToWire();
        var mailbox = origin.PrependLabel("hostmaster"u8).ToWire();
        var numbers = new byte[20];
        foreach (var (offset, value) in new (int, uint)[] { (0, 1), (4, 3600), (8, 600), (12, 86400), (16, 60) })
            BinaryPrimitives.WriteUInt32BigEndian(numbers.AsSpan(offset), value);
        return new DnsRecord(origin, 6, 300, [.. ns, .. mailbox, .. numbers]);
    }

    private static DnsRecord Record(string name, ushort type, byte[] data) => new(DnsName.Parse(name), type, 300, data);
    public void Dispose() { rootKey.Dispose(); childKey.Dispose(); }

    internal sealed class Node : IAsyncDisposable
    {
        private readonly UdpClient udp;
        private readonly TcpListener tcp;
        private readonly CancellationTokenSource closure;
        private readonly bool forceTcp;
        private readonly bool corrupt;
        private Task[] workers = [];
        internal Node(bool ipv6, bool forceTcp, bool corrupt, CancellationToken token)
        {
            udp = DnssecUpstreamFixture.Bind(ipv6);
            Server = DnssecUpstreamFixture.Endpoint(udp);
            tcp = new TcpListener(new IPEndPoint(new IPAddress(Server.GetAddress()), Server.Port));
            if (ipv6) tcp.Server.DualMode = false;
            closure = CancellationTokenSource.CreateLinkedTokenSource(token);
            this.forceTcp = forceTcp;
            this.corrupt = corrupt;
            try { tcp.Start(); }
            catch { udp.Dispose(); tcp.Dispose(); closure.Dispose(); throw; }
        }
        internal DnsServerEndpoint Server { get; }
        internal ConcurrentQueue<(DnsQuestion Question, bool Tcp)> Requests { get; } = new();
        internal void Start(AuthoritativeCatalog catalog)
        {
            if (workers.Length != 0) throw new InvalidOperationException("Owned node already started.");
            workers = [UdpAsync(catalog), TcpAsync(catalog)];
        }
        private async Task UdpAsync(AuthoritativeCatalog catalog)
        {
            try
            {
                while (true)
                {
                    var request = await udp.ReceiveAsync(closure.Token).ConfigureAwait(false);
                    var (question, end) = Query(request.Buffer);
                    Requests.Enqueue((question, false));
                    var response = Encode(request.Buffer, end, catalog.Resolve(question, dnssecOk: true), corrupt);
                    if (forceTcp)
                    {
                        response = request.Buffer[..end];
                        DnssecUpstreamFixture.Write16(response, 2, 0x8630);
                        DnssecUpstreamFixture.Write16(response, 6, 0);
                        DnssecUpstreamFixture.Write16(response, 8, 0);
                        DnssecUpstreamFixture.Write16(response, 10, 0);
                    }
                    await udp.SendAsync(response, request.RemoteEndPoint, closure.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
        private async Task TcpAsync(AuthoritativeCatalog catalog)
        {
            try
            {
                while (true)
                {
                    using var peer = await tcp.AcceptTcpClientAsync(closure.Token).ConfigureAwait(false);
                    using var stream = peer.GetStream();
                    var request = await DnssecUpstreamFixture.ReadFrameAsync(stream, closure.Token).ConfigureAwait(false);
                    var (question, end) = Query(request);
                    Requests.Enqueue((question, true));
                    await DnssecUpstreamFixture.SendFrameAsync(stream, Encode(request, end, catalog.Resolve(question, dnssecOk: true), corrupt), closure.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync()
        {
            try { await closure.CancelAsync().ConfigureAwait(false); await Task.WhenAll(workers).ConfigureAwait(false); }
            finally { udp.Dispose(); tcp.Dispose(); closure.Dispose(); }
        }
    }

    private static (DnsQuestion Question, int End) Query(byte[] bytes)
    {
        Assert.Equal(0x10, BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(2)));
        var end = 12;
        while (bytes[end] != 0) end += bytes[end] + 1;
        var name = DnsName.FromWire(bytes.AsSpan(12, end - 11));
        end++;
        var type = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(end));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(end + 2)));
        end += 4;
        Assert.Equal(0x8000, BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(end + 7)));
        return (new DnsQuestion(name, type, 1), end);
    }

    private static byte[] Encode(byte[] query, int end, DnsAnswer answer, bool corrupt)
    {
        var records = answer.Answers.Concat(answer.Authority).Concat(answer.Additional).Select(record => EncodeRecord(record, corrupt)).ToArray();
        var result = new byte[end + records.Sum(record => record.Length) + 11];
        query.AsSpan(0, end).CopyTo(result);
        DnssecUpstreamFixture.Write16(result, 2, (ushort)(0x8030 | (answer.Authoritative ? 0x400 : 0) | answer.ResponseCode));
        DnssecUpstreamFixture.Write16(result, 6, (ushort)answer.Answers.Count);
        DnssecUpstreamFixture.Write16(result, 8, (ushort)answer.Authority.Count);
        DnssecUpstreamFixture.Write16(result, 10, (ushort)(answer.Additional.Count + 1));
        foreach (var record in records) { record.CopyTo(result, end); end += record.Length; }
        DnssecUpstreamFixture.Write16(result, end + 1, 41);
        DnssecUpstreamFixture.Write16(result, end + 3, 1232);
        DnssecUpstreamFixture.Write16(result, end + 7, 0x8000);
        return result;
    }
    private static byte[] EncodeRecord(DnsRecord record, bool corrupt)
    {
        var name = record.GetOwnerWire(); var data = record.GetData();
        if (corrupt && record.Type == 46) data[^1] ^= 1;
        var result = new byte[name.Length + 10 + data.Length];
        name.CopyTo(result, 0);
        DnssecUpstreamFixture.Write16(result, name.Length, record.Type);
        DnssecUpstreamFixture.Write16(result, name.Length + 2, 1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(name.Length + 4), record.Ttl);
        DnssecUpstreamFixture.Write16(result, name.Length + 8, (ushort)data.Length);
        data.CopyTo(result, name.Length + 10);
        return result;
    }
    private sealed class FixedClock : TimeProvider
    {
        public override long GetTimestamp() => 0;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100);
    }
}
