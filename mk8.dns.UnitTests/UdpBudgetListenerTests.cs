using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Presentation;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class UdpBudgetListenerTests
{
    [Theory]
    [InlineData("127.0.0.2")]
    [InlineData("::1")]
    public async Task RealUdpDropsExcessWhilePipelinedTcpRemainsAvailable(string address)
    {
        var ip = IPAddress.Parse(address); using var port = new TcpListener(ip, 0); port.Start();
        var endpoint = (IPEndPoint)port.LocalEndpoint; port.Stop();
        var limiter = new DnsResponseLimiter(new FrozenClock(), responseBurst: 1);
        var application = new AuthoritativeApplication(new AuthoritativeCatalog([Zone()]), new DnsMessageCodecAdapter(), "budget-network", null, null, limiter);
        var listener = new AuthoritativeListener(endpoint, application);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var shutdown = new CancellationTokenSource(); var serving = listener.RunAsync(shutdown.Token);
        try
        {
            var query = Convert.FromHexString("abcd0100000100000000000003777777076578616d706c650000010001");
            // Connection establishment proves the listener bound; a frozen monotonic clock makes drop decisions independent of scheduling.
            using var tcp = new TcpClient(ip.AddressFamily); await tcp.ConnectAsync(ip, endpoint.Port, timeout.Token).ConfigureAwait(true);
            using var udp = new UdpClient(ip.AddressFamily);
            for (var i = 0; i < 20; i++) _ = await udp.SendAsync(query, endpoint, timeout.Token).ConfigureAwait(true);
            var accepted = await udp.ReceiveAsync(timeout.Token).ConfigureAwait(true);
            Assert.Equal(endpoint, accepted.RemoteEndPoint); AssertAnswer(accepted.Buffer);
            using var absent = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token); absent.CancelAfter(TimeSpan.FromMilliseconds(200));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { _ = await udp.ReceiveAsync(absent.Token).ConfigureAwait(true); }).ConfigureAwait(true);
            using var stream = tcp.GetStream(); var frame = new byte[query.Length + 2]; BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)query.Length); query.CopyTo(frame, 2);
            await stream.WriteAsync(frame.Concat(frame).ToArray(), timeout.Token).ConfigureAwait(true);
            for (var i = 0; i < 2; i++)
            {
                var prefix = new byte[2]; await stream.ReadExactlyAsync(prefix, timeout.Token).ConfigureAwait(true);
                var reply = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)]; await stream.ReadExactlyAsync(reply, timeout.Token).ConfigureAwait(true); AssertAnswer(reply);
            }
            Assert.Equal((1L, 19L, 1), limiter.Statistics);
        }
        finally
        {
            await shutdown.CancelAsync().ConfigureAwait(true);
            try { await serving.ConfigureAwait(true); }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }
    }

    private static AuthoritativeZone Zone()
    {
        var origin = DnsName.Parse("example.");
        var soa = DnsName.Parse("ns.example.").ToWire().Concat(DnsName.Parse("hostmaster.example.").ToWire()).Concat(new byte[20]).ToArray();
        return new AuthoritativeZone(origin, [new DnsRecord(origin, 6, 300, soa), new DnsRecord(origin, 2, 300, DnsName.Parse("ns.example.").ToWire()), new DnsRecord(DnsName.Parse("www.example."), 1, 300, [192, 0, 2, 42])]);
    }

    private static void AssertAnswer(byte[] response)
    {
        Assert.Equal(new byte[] { 0xab, 0xcd, 0x85, 0, 0, 1, 0, 1, 0, 0, 0, 0 }, response[..12]);
        Assert.Equal(new byte[] { 192, 0, 2, 42 }, response[^4..]); Assert.Equal(45, response.Length);
    }

    private sealed class FrozenClock : TimeProvider
    {
        public override long TimestampFrequency => 1;
        public override long GetTimestamp() => 0;
    }
}
