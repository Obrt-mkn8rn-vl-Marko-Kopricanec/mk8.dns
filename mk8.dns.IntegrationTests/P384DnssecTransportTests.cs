using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class P384DnssecTransportTests
{
    [Theory]
    [InlineData(false, false, false, false)]
    [InlineData(false, true, false, false)]
    [InlineData(true, false, false, false)]
    [InlineData(true, true, false, false)]
    [InlineData(false, false, true, false)]
    [InlineData(false, true, true, false)]
    [InlineData(true, false, true, false)]
    [InlineData(true, true, true, false)]
    [InlineData(false, false, false, true)]
    [InlineData(false, true, false, true)]
    [InlineData(true, false, false, true)]
    [InlineData(true, true, false, true)]
    public async Task RealTransportAuthenticatesP384AndSha384DsBeforeChildFetch(bool ipv6, bool tcp, bool corrupt, bool p256Child)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15)); using var fixture = new P384DnssecWireFixture(p256Child);
        var root = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var rootLife = root.ConfigureAwait(true);
        var child = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var childLife = child.ConfigureAwait(true);
        root.Start(query => fixture.Reply(query, child.Server, childRole: false, corrupt));
        child.Start(query => fixture.Reply(query, child.Server, childRole: true, corrupt));
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, P384DnssecWireFixture.Verifier, new DnssecTrustAnchor(DnssecKeys.CreateDs(fixture.Key, 0, 4)),
            [root.Server], child.Server.Port, time: fixture.Clock);
        var result = await resolver.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1), deadline.Token).ConfigureAwait(true);
        Assert.Equal(corrupt ? DnssecResolutionOutcome.Failure : DnssecResolutionOutcome.Authenticated, result.Outcome);
        if (corrupt) { Assert.Empty(result.Answers); Assert.Empty(result.Authority); Assert.Empty(child.Requests); }
        else { Assert.Equal((byte)43, Assert.Single(result.Answers).GetData()[^1]); Assert.Equal(fixture.ChildKey.Owner, result.Origin); }
    }
}
