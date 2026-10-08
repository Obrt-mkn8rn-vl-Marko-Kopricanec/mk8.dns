using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class OperationCutTransportTests
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
    public async Task RealAliasRestartsRejectAncestorAnswersAndPermitAuthenticatedChildRouting(bool ipv6, bool tcp, bool dname, bool succeed)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20)); using var zones = new OperationCutWireFixture(dname, succeed);
        var root = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        var child = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var childLifetime = child.ConfigureAwait(true);
        root.Start(query => zones.Reply(query, child.Server, rootRole: true));
        child.Start(query => zones.Reply(query, child.Server, rootRole: false));
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OperationCutWireFixture.Verifier, zones.Anchor, [root.Server], child.Server.Port, time: zones.Clock);
        var result = await resolver.ResolveDnssecAsync(new DnsQuestion(zones.Start, 1, 1), deadline.Token).ConfigureAwait(true);
        Assert.Equal(succeed ? DnssecResolutionOutcome.Authenticated : DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Contains(root.Requests, question => question.Name.Equals(OperationCutWireFixture.Target));
        if (succeed)
        {
            Assert.Equal(dname ? 3 : 2, result.Answers.Count); Assert.Equal(new byte[] { 192, 0, 2, 43 }, result.Answers[^1].GetData());
        }
        else { Assert.Empty(result.Answers); Assert.Empty(result.Authority); }
    }
}
