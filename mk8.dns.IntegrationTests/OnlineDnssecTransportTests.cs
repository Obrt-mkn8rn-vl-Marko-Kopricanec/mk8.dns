using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class OnlineDnssecTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task NativeEvidenceTransportAuthenticatesSelectedRootChildAndAlias(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [root.Server], child.Server.Port, time: zones.Clock);
        foreach (var question in new[] { new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1),
            new DnsQuestion(DnsName.Parse("www.child.example."), 28, 1), new DnsQuestion(DnsName.Parse("missing.child.example."), 1, 1),
            new DnsQuestion(DnsName.Parse("alias.example."), 1, 1), new DnsQuestion(DnsName.Parse("child.example."), 43, 1) })
        {
            var result = await resolver.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
            Assert.Equal(question, result.Question);
        }
        Assert.Contains(root.Requests, request => request.Question.Type == 43 && request.Tcp == tcp);
        Assert.Contains(child.Requests, request => request.Question.Type == 48 && request.Tcp == tcp);
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    public async Task NativeUnsignedAndForgedAdPathsDoNotServeUnvalidatedChild(bool ipv6, bool tcp, bool corrupt)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: !corrupt);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [root.Server], child.Server.Port, time: zones.Clock);
        var result = await resolver.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1), deadline.Token).ConfigureAwait(true);
        Assert.Equal(corrupt ? DnssecResolutionOutcome.Failure : DnssecResolutionOutcome.UnsignedDelegation, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
        Assert.Empty(child.Requests);
    }
}
