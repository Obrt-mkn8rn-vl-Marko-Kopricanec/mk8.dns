using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Mk8.Dns.Domain;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class NativeCheckingDisabledStartupTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(false, true, true)]
    [InlineData(true, false, false)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    public async Task ExplicitExecutableProfilesServeOutsideAnchorScopeWithoutAdAndSignalReleasesJournal(bool material, bool dnssecOk, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var upstreamEndpoint = Assert.IsType<IPEndPoint>(upstream.Client.LocalEndPoint);
        var port = RecursiveStartupFixture.VacantPair();
        using var fixture = new RecursiveStartupFixture(port, upstreamEndpoint.Port);
        fixture.Configuration["checkingDisabledDnssecMaterial"] = material; fixture.Write();
        var host = new HostProcess("mk8.dns.Application", ["--recursive-checking-disabled-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        using var peer = await ConnectAsync(port, host, deadline.Token).ConfigureAwait(true);
        var question = new DnsQuestion(DnsName.Parse("outside.invalid."), 1, 1);
        var request = UpstreamMessageCodec.EncodeDnssecQuery(19, question);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0130);
        if (!dnssecOk) request[^4] &= 0x7f;
        var reply = await ExchangeAsync(upstream, peer, port, question, request, material, dnssecOk, tcp, deadline.Token).ConfigureAwait(true);
        Assert.Equal((ushort)(!material && dnssecOk ? 0x8194 : 0x8190), BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(2)));
        var decoded = UpstreamMessageCodec.DecodeResponse(reply, 19, question).Answer;
        if (!material && dnssecOk) { Assert.Empty(decoded.Answers); Assert.Equal(0, upstream.Available); }
        else
        {
            Assert.Equal(0, decoded.ResponseCode);
            Assert.Equal([192, 0, 2, 42], Assert.Single(decoded.Answers).GetData());
            Assert.InRange(decoded.Answers[0].Ttl, 1U, 300U);
        }
        await host.StopAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(0, host.ExitCode); fixture.AssertStoreReopens(retention: false);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("type")]
    [InlineData("legacy")]
    [InlineData("refresh")]
    public async Task ClosedProfileConfigurationRefusesBeforeKeyOrStoreIo(string input)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var fixture = new RecursiveStartupFixture(RecursiveStartupFixture.VacantPair(), 53);
        fixture.Configuration["keyFile"] = Path.Combine(fixture.StorePath, "nonexistent-key");
        if (!string.Equals(input, "missing", StringComparison.Ordinal))
        {
            fixture.Configuration["checkingDisabledDnssecMaterial"] = string.Equals(input, "type", StringComparison.Ordinal)
                ? System.Text.Json.Nodes.JsonValue.Create("true") : System.Text.Json.Nodes.JsonValue.Create(value: true);
        }
        fixture.Write();
        var mode = string.Equals(input, "legacy", StringComparison.Ordinal) ? "--recursive-config"
            : string.Equals(input, "refresh", StringComparison.Ordinal) ? "--recursive-refresh-config" : "--recursive-checking-disabled-config";
        var host = new HostProcess("mk8.dns.Application", [mode, fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        await host.WaitForExitAsync(deadline.Token).ConfigureAwait(true);
        Assert.NotEqual(0, host.ExitCode);
        Assert.DoesNotContain("nonexistent-key", await host.ReadLogsAsync(deadline.Token).ConfigureAwait(true), StringComparison.Ordinal);
        fixture.AssertStoreReopens(retention: false);
    }

    private static async Task<byte[]> ExchangeAsync(UdpClient upstream, TcpClient peer, int port, DnsQuestion question,
        byte[] request, bool material, bool dnssecOk, bool tcp, CancellationToken token)
    {
        using var work = CancellationTokenSource.CreateLinkedTokenSource(token);
        var answering = AnswerAsync(upstream, question, material, dnssecOk, work.Token);
        byte[] reply;
        try
        {
            reply = await QueryAsync(peer, port, request, tcp, token).ConfigureAwait(true);
            await answering.ConfigureAwait(true);
        }
        finally
        {
            await work.CancelAsync().ConfigureAwait(true);
            await answering.ConfigureAwait(true);
        }
        return reply;
    }

    private static async Task AnswerAsync(UdpClient upstream, DnsQuestion question, bool material, bool dnssecOk, CancellationToken token)
    {
        if (!material && dnssecOk) return;
        var request = await upstream.ReceiveAsync(token).ConfigureAwait(true);
        var parsed = DnsMessageCodec.DecodeQuery(request.Buffer);
        Assert.Equal(question, parsed.Question); Assert.Equal(material, parsed.DnssecOk);
        Assert.Equal(material ? 0x0010 : 0, parsed.Flags);
        var reply = DnssecUpstreamFixture.Reply(request.Buffer, flags: material ? (ushort)0x8410 : (ushort)0x8400);
        _ = await upstream.SendAsync(reply, request.RemoteEndPoint, token).ConfigureAwait(true);
    }

    private static async Task<byte[]> QueryAsync(TcpClient peer, int port, byte[] request, bool tcp, CancellationToken token)
    {
        if (tcp)
        {
            var stream = peer.GetStream();
            await DnssecUpstreamFixture.SendFrameAsync(stream, request, token).ConfigureAwait(true);
            return await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
        }
        using var client = new UdpClient(); client.Connect(IPAddress.Loopback, port);
        _ = await client.SendAsync(request, token).ConfigureAwait(true); return (await client.ReceiveAsync(token).ConfigureAwait(true)).Buffer;
    }

    private static async Task<TcpClient> ConnectAsync(int port, HostProcess host, CancellationToken token)
    {
        while (!host.HasExited)
        {
            var peer = new TcpClient(AddressFamily.InterNetwork);
            try { await peer.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(true); return peer; }
            catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionRefused)
            { peer.Dispose(); await Task.Delay(TimeSpan.FromMilliseconds(10), token).ConfigureAwait(true); }
            catch { peer.Dispose(); throw; }
        }
        throw new IOException("Owned checking-disabled startup exited before binding: " + await host.ReadLogsAsync(token).ConfigureAwait(true));
    }
}
