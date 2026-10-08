using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class OnlineNsec3TransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task CorrelatedTransportAuthenticatesRootChildNegativeAndWildcardNsec3(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20)); using var fixture = new OnlineNsec3WireFixture();
        var root = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        var child = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var childLifetime = child.ConfigureAwait(true);
        root.Start(query => fixture.Reply(query, child.Server, child: false)); child.Start(query => fixture.Reply(query, child.Server, child: true));
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineNsec3WireFixture.Verifier, fixture.Anchor, [root.Server], child.Server.Port, time: fixture.Clock);
        foreach (var origin in new[] { "example.", "child.example." })
            foreach (var (prefix, type, code) in new (string, ushort, byte)[] { ("missing.empty.", 1, 3), ("www.", 28, 0), ("empty.", 1, 0), ("new.", 1, 0), ("new.", 28, 0) })
            {
                var question = new DnsQuestion(DnsName.Parse(prefix + origin), type, 1);
                var result = await resolver.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
                Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome); Assert.Equal(code, result.ResponseCode);
                Assert.Equal(DnsName.Parse(origin), result.Origin);
            }
        Assert.Contains(child.Requests, request => request.Type == 48); Assert.Contains(root.Requests, request => request.Type == 43);
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(true, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, true, true)]
    public async Task ExactAndOptOutProofsNeverFetchOrServeUnsignedChild(bool ipv6, bool tcp, bool optOut)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15)); using var fixture = new OnlineNsec3WireFixture(unsigned: true, optOut);
        var root = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        var child = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var childLifetime = child.ConfigureAwait(true);
        root.Start(query => fixture.Reply(query, child.Server, child: false)); child.Start(query => fixture.Reply(query, child.Server, child: true));
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineNsec3WireFixture.Verifier, fixture.Anchor, [root.Server], child.Server.Port, time: fixture.Clock);
        var result = await resolver.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1), deadline.Token).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.UnsignedDelegation, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.Empty(child.Requests); Assert.Equal(DnsName.Parse("child.example."), result.UnsignedDelegation);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task CorruptedNsec3DespiteUpstreamAdRefusesOnBothTransports(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15)); using var fixture = new OnlineNsec3WireFixture();
        var root = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        root.Start(query => fixture.Reply(query, root.Server, child: false, corrupt: true));
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineNsec3WireFixture.Verifier, fixture.Anchor, [root.Server], time: fixture.Clock);
        var result = await resolver.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("missing.example."), 1, 1), deadline.Token).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers); Assert.Empty(result.Authority);
    }
}
