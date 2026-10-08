using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class RootPrimingTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task NativeRootPrimingHintsBootstrapAnIndependentlyValidatingResolver(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new RootPrimingWireFixture(ipv6);
        var node = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var nodeLifetime = node.ConfigureAwait(true);
        node.Start(zones.Catalog);
        var upstream = new DnssecUpstreamClient(server => server.Equals(node.Server), TimeSpan.FromSeconds(3));
        var primer = new DnssecRootPrimer(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [node.Server], node.Server.Port, time: zones.Clock);
        var hints = Assert.IsType<DnsRootPrimingResult>(await primer.PrimeAsync(deadline.Token).ConfigureAwait(true));
        Assert.False(hints.AddressesAuthenticated);
        Assert.Equal(2, hints.NameServers.Count);
        Assert.Equal(2, hints.RoutingHints.Count);
        Assert.Empty(hints.UnresolvedNames);
        Assert.True(hints.RemainingTtl > 0);
        Assert.All(hints.RoutingHints, hint => Assert.Equal(node.Server, hint.Server));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor,
            hints.RoutingHints.Select(hint => hint.Server).Distinct(), node.Server.Port, time: zones.Clock);
        var result = await resolver.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.fixture."), 1, 1), deadline.Token).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(new byte[] { 192, 0, 2, 43 }, Assert.Single(result.Answers).GetData());
        Assert.Contains(node.Requests, request => request.Question.Type == 2 && request.Tcp == tcp);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task NativeForgedRootSignatureCannotPrimeAnyEndpoint(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new RootPrimingWireFixture(ipv6);
        var node = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: true, deadline.Token);
        await using var nodeLifetime = node.ConfigureAwait(true);
        node.Start(zones.Catalog);
        var upstream = new DnssecUpstreamClient(server => server.Equals(node.Server), TimeSpan.FromSeconds(3));
        var primer = new DnssecRootPrimer(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [node.Server], node.Server.Port, time: zones.Clock);
        Assert.Null(await primer.PrimeAsync(deadline.Token).ConfigureAwait(true));
        Assert.DoesNotContain(node.Requests, request => request.Question.Type == 2);
    }
}
