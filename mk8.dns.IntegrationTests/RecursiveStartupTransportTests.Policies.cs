using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Infrastructure.Cryptography;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed partial class RecursiveStartupTransportTests
{
    [Theory]
    [InlineData(1, 1048576, 6)]
    [InlineData(2, 1048576, 4)]
    [InlineData(2, 1, 6)]
    public async Task ExecutableAppliesCacheCapacityAndTtlPolicy(int maximumEntries, long maximumBytes, int exchanges)
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
        fixture.Configuration["cachePolicy"] = new JsonObject
        {
            ["maximumEntries"] = maximumEntries,
            ["maximumPayloadBytes"] = maximumBytes,
            ["maximumPositiveTtl"] = 120,
            ["maximumNegativeTtl"] = 30,
        };
        // Three sequential requests must not be refused because a completed
        // coalescer worker has yet to release its separate accounting charge.
        fixture.Configuration["maximumWorkers"] = 4;
        fixture.Configuration["maximumTcpMessages"] = 4;
        fixture.Write();
        var host = new HostProcess("mk8.dns.Application", ["--recursive-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        using var peer = await ConnectAsync(port, host, deadline.Token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        var endpoint = new DnsServerEndpoint(IPAddress.Loopback.GetAddressBytes(), (ushort)port);
        foreach (var name in new[] { "www.example.", "missing.example.", "www.example." })
        {
            var negative = string.Equals(name, "missing.example.", StringComparison.Ordinal);
            var response = await ExchangeAsync(stream, new DnsQuestion(DnsName.Parse(name), 1, 1), endpoint, deadline.Token).ConfigureAwait(true);
            Assert.Equal(negative ? 3 : 0, response.ResponseCode);
            Assert.Equal(32, response.Flags & 32);
            var records = response.Answers.Concat(response.Authority).ToArray();
            Assert.NotEmpty(records);
            Assert.All(records, record => Assert.InRange(record.Ttl, 1U, negative ? 30U : 120U));
            if (!negative) Assert.Equal([192, 0, 2, 42], Assert.Single(response.Answers, record => record.Type == 1).GetData());
        }
        Assert.Equal(exchanges, root.Requests.Count);
        await host.StopAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(0, host.ExitCode); fixture.AssertStoreReopens(retention: false);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ExecutableSpendsTheConfiguredValidatingExchangeBudget(int maximumExchanges)
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
        fixture.Configuration["iterationPolicy"] = new JsonObject
        {
            ["maximumExchanges"] = maximumExchanges,
            ["maximumAliasHops"] = 16,
            ["maximumVerificationAttempts"] = 512,
        };
        fixture.Write();
        var host = new HostProcess("mk8.dns.Application", ["--recursive-config", fixture.ConfigurationPath], 0);
        await using var lifetime = host.ConfigureAwait(true);
        using var peer = await ConnectAsync(port, host, deadline.Token).ConfigureAwait(true);
        var stream = peer.GetStream(); await using var streamLifetime = stream.ConfigureAwait(true);
        var question = new DnsQuestion(DnsName.Parse("www.example."), 1, 1);
        var endpoint = new DnsServerEndpoint(IPAddress.Loopback.GetAddressBytes(), (ushort)port);
        var response = await ExchangeAsync(stream, question, endpoint, deadline.Token).ConfigureAwait(true);
        Assert.Equal(maximumExchanges == 1 ? 2 : 0, response.ResponseCode);
        Assert.Equal(maximumExchanges == 1 ? 0 : 32, response.Flags & 32);
        Assert.Equal(maximumExchanges, root.Requests.Count);
        if (maximumExchanges == 1) Assert.Empty(response.Answers);
        else Assert.Equal([192, 0, 2, 42], Assert.Single(response.Answers, record => record.Type == 1).GetData());
        await host.StopAsync(deadline.Token).ConfigureAwait(true);
        Assert.Equal(0, host.ExitCode); fixture.AssertStoreReopens(retention: false);
    }

    private static async Task<DnsUpstreamEvidence> ExchangeAsync(NetworkStream stream, DnsQuestion question,
        DnsServerEndpoint endpoint, CancellationToken token)
    {
        var request = UpstreamMessageCodec.EncodeDnssecQuery(19, question);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0x0100);
        await DnssecUpstreamFixture.SendFrameAsync(stream, request, token).ConfigureAwait(true);
        var response = await DnssecUpstreamFixture.ReadFrameAsync(stream, token).ConfigureAwait(true);
        var decoded = UpstreamMessageCodec.DecodeDnssecResponse(response, 19, question, endpoint);
        Assert.False(decoded.Truncated);
        return decoded.Evidence;
    }
}
