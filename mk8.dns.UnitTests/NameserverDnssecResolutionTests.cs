using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class NameserverDnssecResolutionTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task SignedExternalAddressCanRouteWithoutLeakingInfrastructure(bool providerZone, bool ipv6)
    {
        using var fixture = new NameserverDnssecFixture();
        if (!providerZone) fixture.Target = DnsName.Parse("ns.example.");
        if (ipv6) fixture.Address = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(NameserverDnssecFixture.Question.Name, Assert.Single(result.Answers).Owner);
        Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.GetAddress().SequenceEqual(new byte[] { 127, 0, 0, 99 }));
        var calls = fixture.Calls.ToArray();
        var ds = Array.FindIndex(calls, call => call.Question.Type == 43 && call.Question.Name.Equals(DnsName.Parse("child.example.")));
        var lookup = Array.FindIndex(calls, call => call.Question.Name.Equals(fixture.Target));
        var child = Array.FindIndex(calls, call => call.Server.Equals(fixture.ChildServer));
        Assert.True(ds >= 0 && lookup > ds && child > lookup);
    }

    [Theory]
    [InlineData(0U)]
    [InlineData(1U)]
    [InlineData(7U)]
    public async Task RoutingLifetimeCapsClientDataEvenAtZero(uint ttl)
    {
        using var fixture = new NameserverDnssecFixture { AddressTtl = ttl };
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(ttl, result.AuthenticatedTtl); Assert.Equal(ttl, Assert.Single(result.Answers).Ttl);
    }

    [Fact]
    public async Task ExistingInChildGlueDoesNotTriggerAddressDependencies()
    {
        using var fixture = new OnlineDnssecFixture();
        var result = await fixture.Resolver().ResolveDnssecAsync(NameserverDnssecFixture.Question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.DoesNotContain(fixture.Calls, call => call.Question.Name.Equals(DnsName.Parse("ns.child.example.")));
        Assert.Equal(5, fixture.Calls.Count);
    }
}
