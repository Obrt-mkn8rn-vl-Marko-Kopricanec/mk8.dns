using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed partial class RecursiveStartupTransportTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExecutableOpensExistingJournalSharesUdpTcpProofCacheAndJoinsSignalShutdown(bool retention)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var signing = EcdsaP256DnssecSigningKey.Create();
        var name = DnsName.Parse("www.example.");
        var verifier = new DnssecSignatureVerifier();
        var signed = CreateZone(signing, verifier);
        var catalog = new AuthoritativeCatalog([new ZoneContents(signed.Source, signed.GetAllRecords().Where(record => record.Type is 46 or 47 or 48))],
            verifier, TimeProvider.System);
        var root = new OnlineDnssecWireFixture.Node(ipv6: false, forceTcp: false, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        root.Start(catalog);
        var port = RecursiveStartupFixture.VacantPair();
        using var fixture = new RecursiveStartupFixture(port, root.Server.Port, signed.Dnskey, retention);
        fixture.Write();
        var host = new HostProcess("mk8.dns.Application", ["--recursive-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        using var peer = await ConnectAsync(port, host, deadline.Token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        var question = new DnsQuestion(name, 1, 1);
        var request = UpstreamMessageCodec.EncodeDnssecQuery(19, question);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0100);
        await DnssecUpstreamFixture.SendFrameAsync(stream, request, deadline.Token).ConfigureAwait(true);
        var first = await DnssecUpstreamFixture.ReadFrameAsync(stream, deadline.Token).ConfigureAwait(true);
        var calls = root.Requests.Count;
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(IPAddress.Loopback, port);
        _ = await udp.SendAsync(request, deadline.Token).ConfigureAwait(true);
        var second = (await udp.ReceiveAsync(deadline.Token).ConfigureAwait(true)).Buffer;
        var endpoint = new DnsServerEndpoint(IPAddress.Loopback.GetAddressBytes(), (ushort)port);
        AssertReply(first, question, endpoint); AssertReply(second, question, endpoint);
        Assert.Equal(calls, root.Requests.Count);
        await host.StopAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(0, host.ExitCode); fixture.AssertStoreReopens(retention);
    }

    private static void AssertReply(byte[] packet, DnsQuestion question, DnsServerEndpoint endpoint)
    {
        var decoded = UpstreamMessageCodec.DecodeDnssecResponse(packet, 19, question, endpoint);
        Assert.False(decoded.Truncated); Assert.Equal(0, decoded.Evidence.ResponseCode);
        Assert.Equal(32, decoded.Evidence.Flags & 32);
        Assert.Equal([192, 0, 2, 42], Assert.Single(decoded.Evidence.Answers, record => record.Type == 1).GetData());
        Assert.Contains(decoded.Evidence.Answers, record => record.Type == 46);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    public async Task ExecutableMinimisesValidatingQuestionsAndRefusesAtTheStepLimit(int maximumSteps)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var signing = EcdsaP256DnssecSigningKey.Create();
        var verifier = new DnssecSignatureVerifier();
        var signed = CreateZone(signing, verifier, deep: true);
        var root = new OnlineDnssecWireFixture.Node(ipv6: false, forceTcp: false, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        root.Start(new AuthoritativeCatalog([new ZoneContents(signed.Source,
            signed.GetAllRecords().Where(record => record.Type is 46 or 47 or 48))], verifier, TimeProvider.System));
        var port = RecursiveStartupFixture.VacantPair();
        using var fixture = new RecursiveStartupFixture(port, root.Server.Port, signed.Dnskey);
        fixture.Configuration["qnameMinimisation"] = new JsonObject { ["maximumSteps"] = maximumSteps };
        fixture.Write();
        var host = new HostProcess("mk8.dns.Application", ["--recursive-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        using var peer = await ConnectAsync(port, host, deadline.Token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        var question = new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1);
        var request = UpstreamMessageCodec.EncodeDnssecQuery(19, question);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0100);
        await DnssecUpstreamFixture.SendFrameAsync(stream, request, deadline.Token).ConfigureAwait(true);
        var response = await DnssecUpstreamFixture.ReadFrameAsync(stream, deadline.Token).ConfigureAwait(true);
        var endpoint = new DnsServerEndpoint(IPAddress.Loopback.GetAddressBytes(), (ushort)port);
        var requests = root.Requests.Select(item => item.Question).ToArray();
        DnsQuestion[] discovery = [new(DnsName.Parse("example."), 48, 1), new(DnsName.Parse("team.example."), 2, 1)];
        if (maximumSteps == 1)
        {
            var decoded = UpstreamMessageCodec.DecodeDnssecResponse(response, 19, question, endpoint);
            Assert.False(decoded.Truncated);
            Assert.Equal(2, decoded.Evidence.ResponseCode);
            Assert.Equal(0, decoded.Evidence.Flags & 32);
            Assert.Empty(decoded.Evidence.Answers);
            Assert.Equal(discovery, requests);
        }
        else
        {
            AssertReply(response, question, endpoint);
            Assert.Equal([.. discovery, new DnsQuestion(question.Name, 2, 1), question], requests);
        }
        await host.StopAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(0, host.ExitCode); fixture.AssertStoreReopens(retention: false);
    }

    private static SignedZone CreateZone(EcdsaP256DnssecSigningKey signing, DnssecSignatureVerifier verifier, bool deep = false)
    {
        var origin = DnsName.Parse("example.");
        var soa = new byte[20];
        foreach (var (offset, number) in new (int, uint)[] { (0, 1), (4, 3600), (8, 600), (12, 86400), (16, 60) })
            BinaryPrimitives.WriteUInt32BigEndian(soa.AsSpan(offset), number);
        var ns = DnsName.Parse("ns.example.");
        DnsRecord[] extra = deep
            ? [new DnsRecord(DnsName.Parse("team.example."), 16, 300, [1, (byte)'x']),
                new DnsRecord(DnsName.Parse("private.team.example."), 1, 300, [192, 0, 2, 42])]
            : [];
        var zone = new AuthoritativeZone(origin,
            [new DnsRecord(origin, 6, 300, [.. ns.ToWire(), .. DnsName.Parse("hostmaster.example.").ToWire(), .. soa]),
                new DnsRecord(origin, 2, 300, ns.ToWire()), new DnsRecord(ns, 1, 300, [127, 0, 0, 1]),
                new DnsRecord(DnsName.Parse("www.example."), 1, 300, [192, 0, 2, 42]), .. extra]);
        var now = checked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        return NsecZoneSigner.Sign(zone, signing, verifier, new DnssecSignatureWindow(now - 60, now + 3600));
    }

    [Fact]
    public async Task ExplicitEmptyAccessPolicyDeniesBeforeUpstreamWorkAndSignalReleasesLease()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var signing = EcdsaP256DnssecSigningKey.Create();
        var verifier = new DnssecSignatureVerifier();
        var signed = CreateZone(signing, verifier);
        var root = new OnlineDnssecWireFixture.Node(ipv6: false, forceTcp: false, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        root.Start(new AuthoritativeCatalog([new ZoneContents(signed.Source,
            signed.GetAllRecords().Where(record => record.Type is 46 or 47 or 48))], verifier, TimeProvider.System));
        var port = RecursiveStartupFixture.VacantPair();
        using var fixture = new RecursiveStartupFixture(port, root.Server.Port, signed.Dnskey);
        fixture.Configuration["clientNetworks"] = new JsonArray(); fixture.Write();
        var host = new HostProcess("mk8.dns.Application", ["--recursive-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        using var peer = await ConnectAsync(port, host, deadline.Token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(true));
        Assert.Empty(root.Requests);
        await host.StopAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(0, host.ExitCode); fixture.AssertStoreReopens(retention: false);
    }

    private static async Task<TcpClient> ConnectAsync(int port, HostProcess host, CancellationToken token)
    {
        while (!host.HasExited)
        {
            var peer = new TcpClient(AddressFamily.InterNetwork);
            try { await peer.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(true); return peer; }
            catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionRefused)
            {
                peer.Dispose(); await Task.Delay(TimeSpan.FromMilliseconds(10), token).ConfigureAwait(true);
            }
            catch { peer.Dispose(); throw; }
        }
        throw new IOException("Owned recursive startup exited before the requested bind: " + await host.ReadLogsAsync(token).ConfigureAwait(true));
    }
}
