using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class OnlineDnssecDnameTransportTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task NativeTransportAuthenticatesDnameAndItsCrossCutTargets(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: false, dname: true);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        var child = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var childLifetime = child.ConfigureAwait(true);
        root.Start(zones.Root); child.Start(zones.Child);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [root.Server], child.Server.Port, time: zones.Clock);
        foreach (var (name, type, code) in new (string, ushort, byte)[] { ("www.branch.example.", 1, 0),
            ("www.branch.child.example.", 1, 0), ("www.branch.example.", 5, 0), ("missing.branch.example.", 1, 3),
            ("www.branch.example.", 28, 0), ("branch.example.", 39, 0) })
        {
            var question = new DnsQuestion(DnsName.Parse(name), type, 1);
            var result = await resolver.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
            Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
            Assert.Equal(code, result.ResponseCode);
            if (type == 39) Assert.Equal(39, Assert.Single(result.Answers).Type);
            else
            {
                Assert.Equal(39, result.Answers[0].Type);
                Assert.Equal(5, result.Answers[1].Type);
                Assert.Equal(question.Name, result.Answers[1].Owner);
                if (name.StartsWith("missing", StringComparison.Ordinal) || type == 28) Assert.Equal(6, Assert.Single(result.Authority).Type);
            }
        }
        Assert.Contains(root.Requests, request => request.Question.Type == 43 && request.Tcp == tcp);
        Assert.Contains(child.Requests, request => request.Question.Type == 48 && request.Tcp == tcp);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task AuthenticatedDnameToUnsignedDelegationProducesNoChildAnswer(bool ipv6, bool tcp)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var zones = new OnlineDnssecWireFixture(ipv6, unsigned: true, dname: true);
        var root = new OnlineDnssecWireFixture.Node(ipv6, tcp, corrupt: false, deadline.Token);
        await using var rootLifetime = root.ConfigureAwait(true);
        root.Start(zones.Root);
        var upstream = new DnssecUpstreamClient(server => server.Equals(root.Server), TimeSpan.FromSeconds(3));
        var resolver = new DnssecIterativeResolver(upstream, OnlineDnssecWireFixture.Verifier, zones.Anchor, [root.Server], time: zones.Clock);
        var result = await resolver.ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.branch.example."), 1, 1), deadline.Token).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.UnsignedDelegation, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
        Assert.Contains(root.Requests, request => request.Question.Type == 43 && request.Tcp == tcp);
    }
}
