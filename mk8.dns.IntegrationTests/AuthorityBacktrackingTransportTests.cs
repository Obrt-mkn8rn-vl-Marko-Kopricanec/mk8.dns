using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Wire;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class AuthorityBacktrackingTransportTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    public async Task NativeTransportBacktracksAfterAuthenticatedChildFailureAndStillRejectsForgedDs(bool ipv6, bool tcp, bool corruptDs)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20)); using var fixture = new NameserverDnssecWireFixture();
        var first = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var firstLifetime = first.ConfigureAwait(true);
        var second = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var secondLifetime = second.ConfigureAwait(true);
        var child = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var childLifetime = child.ConfigureAwait(true);
        var alternate = false; var question = new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1);
        first.Start(query => fixture.Reply(query, child.Server, rootRole: true, defect: 0));
        second.Start(query =>
        {
            if (DnsMessageCodec.DecodeQuery(query).Question!.Equals(question)) Volatile.Write(ref alternate, true);
            return fixture.Reply(query, child.Server, rootRole: true, defect: corruptDs ? 1 : 0);
        });
        child.Start(query => DnsMessageCodec.DecodeQuery(query).Question!.Equals(question) && !Volatile.Read(ref alternate)
            ? DnssecUpstreamFixture.Reply(query, flags: 0x8432)
            : fixture.Reply(query, child.Server, rootRole: false, defect: 0));
        var upstream = new DnssecUpstreamClient(server => server.Equals(first.Server) || server.Equals(second.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, NameserverDnssecWireFixture.Verifier, fixture.Anchor,
            [first.Server, second.Server], child.Server.Port, time: fixture.Clock);
        var result = await resolver.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
        Assert.Contains(second.Requests, request => request.Equals(question));
        Assert.Contains(child.Requests, request => request.Name.Equals(DnsName.Parse("child.example.")) && request.Type == 48);
        Assert.Equal(corruptDs ? DnssecResolutionOutcome.Failure : DnssecResolutionOutcome.Authenticated, result.Outcome);
        if (corruptDs) { Assert.Empty(result.Answers); Assert.Empty(result.Authority); }
        else
        {
            Assert.Equal([192, 0, 2, 43], Assert.Single(result.Answers).GetData());
            Assert.Equal(7U, result.AuthenticatedTtl); Assert.Equal(7U, result.Answers[0].Ttl);
        }
    }
}
