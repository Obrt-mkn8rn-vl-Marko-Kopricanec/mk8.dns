using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class NameserverDnssecTransportTests
{
    [Theory]
    [InlineData(false, false, 0)]
    [InlineData(false, true, 0)]
    [InlineData(true, false, 0)]
    [InlineData(true, true, 0)]
    [InlineData(false, false, 1)]
    [InlineData(false, true, 1)]
    [InlineData(true, false, 1)]
    [InlineData(true, true, 1)]
    [InlineData(false, false, 2)]
    [InlineData(false, true, 2)]
    [InlineData(true, false, 2)]
    [InlineData(true, true, 2)]
    public async Task NativeTransportDiscoversAnAuthenticatedExternalNsAndRejectsCorruption(bool ipv6, bool tcp, int defect)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20)); using var fixture = new NameserverDnssecWireFixture();
        var root = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        var authority = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var authorityLifetime = authority.ConfigureAwait(true);
        root.Start(query => fixture.Reply(query, authority.Server, rootRole: true, defect));
        authority.Start(query => fixture.Reply(query, authority.Server, rootRole: false, defect));
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(authority.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, NameserverDnssecWireFixture.Verifier, fixture.Anchor,
            [root.Server], authority.Server.Port, time: fixture.Clock);
        var question = new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1);
        var result = await resolver.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
        Assert.Equal(defect == 0 ? DnssecResolutionOutcome.Authenticated : DnssecResolutionOutcome.Failure, result.Outcome);
        if (defect == 0)
        {
            var answer = Assert.Single(result.Answers); Assert.Equal(question.Name, answer.Owner); Assert.Equal(7U, answer.Ttl);
            Assert.Equal(7U, result.AuthenticatedTtl); Assert.Empty(result.Authority);
            Assert.Contains(authority.Requests, request => request.Name.Equals(DnsName.Parse("ns.provider.example.")));
            Assert.Contains(authority.Requests, request => request.Name.Equals(DnsName.Parse("child.example.")) && request.Type == 48);
        }
        else
        {
            Assert.Empty(result.Answers); Assert.Empty(result.Authority);
            Assert.DoesNotContain(authority.Requests, request => request.Name.IsSubdomainOf(DnsName.Parse("child.example.")));
        }
    }
}
