using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class QnameMinimisationEdgeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthenticatedDiscoveryAliasesAreConservativelyRefused(bool dname)
    {
        using var fixture = new QnameMinimisationFixture();
        fixture.Transform = (question, server, reply) =>
        {
            if (question.Type != 2) return reply;
            var record = new DnsRecord(dname ? fixture.Source.Root : question.Name, dname ? (ushort)39 : (ushort)5,
                300, DnsName.Parse("other.example.").ToWire());
            return OnlineDnssecFixture.Reply(question, server, [record, fixture.Source.Sign([record])]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type == 1);
    }

    [Fact]
    public async Task ExactAuthenticatedNsMembershipCanAdvanceDiscovery()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.team.example.");
        fixture.Transform = (question, server, reply) =>
        {
            if (question.Type != 2) return reply;
            var record = new DnsRecord(question.Name, 2, 300, DnsName.Parse("ns.example.").ToWire());
            return OnlineDnssecFixture.Reply(question, server, [record, fixture.Source.Sign([record])]);
        };
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal((ushort)1, Assert.Single(result.Answers).Type); Assert.Empty(result.Authority);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task FinalOriginalQueryStillAuthenticatesNegativeData(int mode)
    {
        using var fixture = new QnameMinimisationFixture();
        var question = new DnsQuestion(DnsName.Parse(mode == 0 ? "www.example." : "absent.example."), mode == 0 ? (ushort)28 : (ushort)1, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(mode == 0 ? (byte)0 : (byte)3, result.ResponseCode);
        Assert.Empty(result.Answers); Assert.Single(result.Authority);
    }

    [Fact]
    public async Task EscapedOctetLabelIsShortenedOnWholeWireLabelBoundaries()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.a\\046b.example.");
        var question = new DnsQuestion(DnsName.Parse("private.a\\046b.example."), 1, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(DnsName.Parse("a\\046b.example."), fixture.Calls[1].Question.Name);
        Assert.Equal(2, fixture.Calls[1].Question.Name.LabelCount);
    }

    [Fact]
    public async Task DescendantDsDiscoversOnlyItsParentAuthorityAndRetainsChildSideNoData()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("www.child.example.", child: true);
        var question = new DnsQuestion(DnsName.Parse("www.child.example."), 43, 1);
        var result = await fixture.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Empty(result.Answers); Assert.Single(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Type == 2 && call.Question.Name.Equals(question.Name));
        Assert.Contains(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer) && call.Question.Equals(question));
    }

    [Fact]
    public async Task ZeroDiscoveryLifetimeCanAuthenticateButCannotSupplyCacheReuse()
    {
        using var fixture = new QnameMinimisationFixture(); fixture.AddAddress("private.team.example.");
        fixture.Transform = (question, server, reply) => question.Type == 2
            ? OnlineDnssecFixture.Copy(reply, authority: reply.Authority.Select(record => record.WithTtl(0)).ToArray()) : reply;
        var resolver = fixture.Resolver(); var cache = new CachingDnssecResolver(resolver); await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = new DnsQuestion(DnsName.Parse("private.team.example."), 1, 1);
        var result = await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(0u, result.AuthenticatedTtl); Assert.Equal(0u, Assert.Single(result.Answers).Ttl);
        Assert.Equal(0, cache.Statistics.Entries);
    }
}
