using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class QnameMinimisationTransportTests
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
    [InlineData(false, false, true, true)]
    [InlineData(false, true, true, true)]
    [InlineData(true, false, true, true)]
    [InlineData(true, true, true, true)]
    public async Task RealDiscoveryPreservesQueryPrivacyAndRequiresAuthenticatedProgress(bool ipv6, bool tcp, bool corrupt, bool deep)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20)); using var zones = new QnameMinimisationWireFixture(corrupt, deep);
        var root = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        var child = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var childLifetime = child.ConfigureAwait(true);
        root.Start(query => zones.Reply(query, child.Server, rootRole: true));
        child.Start(query => zones.Reply(query, child.Server, rootRole: false));
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = DnssecIterativeResolver.CreateWithQnameMinimisation(upstream, QnameMinimisationWireFixture.Verifier,
            zones.Anchor, [root.Server], new DnsQnameMinimisationPolicy(), child.Server.Port, time: zones.Clock);
        var result = await resolver.ResolveDnssecAsync(new DnsQuestion(zones.Name, 1, 1), deadline.Token).ConfigureAwait(true);
        Assert.Equal(corrupt ? DnssecResolutionOutcome.Failure : DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Contains(root.Requests, question => question.Type == 2 && question.Name.Equals(DnsName.Parse(deep ? "team.example." : "child.example.")));
        if (!deep) Assert.DoesNotContain(root.Requests, question => question.Name.Equals(zones.Name));
        if (corrupt)
        {
            Assert.Empty(result.Answers); Assert.Empty(result.Authority);
            Assert.DoesNotContain(root.Requests.Concat(child.Requests), question => question.Type == 1);
        }
        else Assert.Equal(new byte[] { 192, 0, 2, 43 }, Assert.Single(result.Answers).GetData());
    }
}
