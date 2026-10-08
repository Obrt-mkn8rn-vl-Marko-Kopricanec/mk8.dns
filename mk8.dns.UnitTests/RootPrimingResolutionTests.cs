using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RootPrimingResolutionTests
{
    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 2)]
    [InlineData(false, 13)]
    [InlineData(true, 16)]
    [InlineData(false, 32)]
    public async Task AuthenticatedNsMembershipDoesNotAuthenticateRoutingAddresses(bool ds, int names)
    {
        using var fixture = new RootPrimingFixture(names);
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer(ds).PrimeAsync(CancellationToken.None));
        Assert.Equal(names, result.NameServers.Count);
        Assert.Equal(Math.Min(32, 2 * names), result.RoutingHints.Count);
        Assert.Equal(Math.Max(0, names - 16), result.UnresolvedNames.Count);
        Assert.Equal(300U, result.RemainingTtl);
        Assert.False(result.AddressesAuthenticated);
        Assert.Equal(RootPrimingFixture.Server, result.Source);
        Assert.All(result.RoutingHints, hint => Assert.Equal(DnsRootHintSource.Additional, hint.Source));
        Assert.Equal(new ushort[] { 48, 2 }, fixture.Calls.Select(call => call.Question.Type));
        Assert.All(fixture.Calls, call => Assert.Equal(RootPrimingFixture.Root, call.Question.Name));
    }

    [Fact]
    public async Task MissingAddressFamiliesUseSameConfiguredBootstrapAfterNsAuthentication()
    {
        using var fixture = new RootPrimingFixture();
        fixture.Additional = [fixture.Addresses[0]];
        var verifier = new DnssecChainFixture.CountingVerifier();
        fixture.Override = (question, server, _) =>
        {
            if (question.Type is 1 or 28) Assert.True(verifier.Calls >= 2);
            return ValueTask.FromResult(fixture.Default(question, server));
        };
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer(verifier: verifier).PrimeAsync(CancellationToken.None));
        Assert.Equal(4, result.RoutingHints.Count);
        Assert.Single(result.RoutingHints, hint => hint.Source == DnsRootHintSource.Additional);
        Assert.Equal(3, result.RoutingHints.Count(hint => hint.Source == DnsRootHintSource.DirectAddressAnswer));
        Assert.Equal(new ushort[] { 48, 2, 28, 1, 28 }, fixture.Calls.Select(call => call.Question.Type));
        Assert.All(fixture.Calls, call => Assert.Equal(RootPrimingFixture.Server, call.Server));
    }

    [Fact]
    public async Task UnrelatedAdditionalCannotBecomeANameOrEndpoint()
    {
        using var fixture = new RootPrimingFixture(1);
        fixture.Additional = [.. fixture.Addresses, DnssecFixture.A("unrelated.fixture.", 99)];
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(2, result.RoutingHints.Count);
        Assert.DoesNotContain(result.RoutingHints, hint => hint.Name.Equals(DnsName.Parse("unrelated.fixture.")));
        Assert.Equal(2, fixture.Calls.Count);
    }

    [Fact]
    public async Task PartialHintResultExplicitlyListsUnresolvedAuthenticatedNames()
    {
        using var fixture = new RootPrimingFixture();
        fixture.Addresses.RemoveAll(record => record.Owner.Equals(DnsName.Parse("ns1.fixture.")));
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(2, result.NameServers.Count);
        Assert.Equal("ns1.fixture.", Assert.Single(result.UnresolvedNames).ToString());
        Assert.Equal(2, result.RoutingHints.Count);
        Assert.Equal(4, fixture.Calls.Count);
    }

    [Fact]
    public async Task ImmutableSnapshotsOwnCollectionsAndEndpointOctets()
    {
        using var fixture = new RootPrimingFixture();
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer().PrimeAsync(CancellationToken.None));
        fixture.NameServers.Clear(); fixture.Addresses.Clear();
        result.RoutingHints[0].Server.GetAddress()[0] = 0;
        Assert.Equal(192, result.RoutingHints[0].Server.GetAddress()[0]);
        Assert.Throws<NotSupportedException>(() => ((IList<DnsName>)result.NameServers).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<DnsRootRoutingHint>)result.RoutingHints).Clear());
        Assert.False(typeof(IDnsResolver).IsAssignableFrom(typeof(DnssecRootPrimer)));
    }

    [Fact]
    public async Task UnauthenticatedAddressChangeRemainsExplicitlyRoutingOnly()
    {
        using var fixture = new RootPrimingFixture(1);
        fixture.Additional = fixture.Addresses.Select(record => record.Type == 1 ? record.WithTtl(5) : record).ToArray();
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.False(result.AddressesAuthenticated);
        Assert.Equal(5U, result.RemainingTtl);
        Assert.Equal(2, fixture.Calls.Count);
    }
}
