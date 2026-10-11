using System.Buffers.Binary;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

// Dedicated owned fixture for BOTH ordinary CD0/DO0 and validating CD1/DO1
// iterative acquisition. No existing fixture or production query policy changes.
internal sealed class CheckingDisabledWireNode : IAsyncDisposable
{
    private readonly UdpClient udp;
    private readonly TcpListener tcp;
    private readonly CancellationTokenSource closure;
    private readonly bool forceTcp;
    private Task[] workers = [];

    internal CheckingDisabledWireNode(bool ipv6, bool forceTcp, CancellationToken token)
    {
        (udp, tcp) = DnssecUpstreamFixture.BindPair(ipv6);
        Server = DnssecUpstreamFixture.Endpoint(udp);
        closure = CancellationTokenSource.CreateLinkedTokenSource(token);
        this.forceTcp = forceTcp;
    }
    internal DnsServerEndpoint Server { get; }

    internal void Start(AuthoritativeCatalog catalog)
    {
        if (workers.Length != 0) throw new InvalidOperationException("Owned fixture already started.");
        workers = [UdpAsync(catalog), TcpAsync(catalog)];
    }

    private async Task UdpAsync(AuthoritativeCatalog catalog)
    {
        try
        {
            while (true)
            {
                var received = await udp.ReceiveAsync(closure.Token).ConfigureAwait(false);
                var response = Respond(received.Buffer, catalog, forceTcp);
                await udp.SendAsync(response, received.RemoteEndPoint, closure.Token).ConfigureAwait(false);
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
                using var client = await tcp.AcceptTcpClientAsync(closure.Token).ConfigureAwait(false);
                var stream = client.GetStream(); await using var lifetime = stream.ConfigureAwait(false);
                var request = await DnssecUpstreamFixture.ReadFrameAsync(stream, closure.Token).ConfigureAwait(false);
                await DnssecUpstreamFixture.SendFrameAsync(stream, Respond(request, catalog, truncated: false), closure.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (closure.IsCancellationRequested) { }
    }

    private static byte[] Respond(byte[] request, AuthoritativeCatalog catalog, bool truncated)
    {
        var query = DnsMessageCodec.DecodeQuery(request);
        var question = Assert.IsType<DnsQuestion>(query.Question);
        Assert.Equal(query.DnssecOk ? 0x0010 : 0, query.Flags);
        var answer = catalog.Resolve(question, dnssecOk: query.DnssecOk);
        var selected = truncated ? new DnsAnswer(0, authoritative: true, [], [], []) : new DnsAnswer(answer.ResponseCode, answer.Authoritative,
            answer.Answers.Select(CorruptSignature), answer.Authority.Select(CorruptSignature), answer.Additional.Select(CorruptSignature));
        var response = DnsMessageCodec.EncodeResponse(query, selected, tcp: !truncated);
        if (truncated)
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) | 0x0200));
        return response;
    }

    private static DnsRecord CorruptSignature(DnsRecord record)
    {
        if (record.Type != 46) return record;
        var data = record.GetData(); data[^1] ^= 1;
        return new(record.Owner, record.Type, record.Ttl, data);
    }

    public async ValueTask DisposeAsync()
    {
        try { await closure.CancelAsync().ConfigureAwait(false); await Task.WhenAll(workers).ConfigureAwait(false); }
        finally { udp.Dispose(); tcp.Stop(); closure.Dispose(); }
    }
}
