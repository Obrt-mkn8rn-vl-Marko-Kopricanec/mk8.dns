using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecResolutionTests
{
    [Theory]
    [InlineData(false, "www.example.", 2)]
    [InlineData(true, "www.example.", 2)]
    [InlineData(false, "www.child.example.", 5)]
    [InlineData(true, "www.child.example.", 5)]
    public async Task StaticAnchorAuthenticatesActualSelectedChain(bool ds, string name, int exchanges)
    {
        ArgumentNullException.ThrowIfNull(name);
        using var fixture = new OnlineDnssecFixture();
        var question = new DnsQuestion(DnsName.Parse(name), 1, 1);
        var result = await fixture.Resolver(ds).ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(question, result.Question);
        Assert.Equal(name, Assert.Single(result.Answers).Owner.ToString());
        Assert.Equal(name.Contains("child", StringComparison.Ordinal) ? fixture.Child : fixture.Root, result.Origin);
        Assert.Equal(exchanges, fixture.Calls.Count);
        Assert.True(result.AuthenticatedTtl > 0);
        Assert.Null(result.UnsignedDelegation);
    }

    [Theory]
    [InlineData("www.example.", 28, 0)]
    [InlineData("missing.example.", 1, 3)]
    [InlineData("www.child.example.", 28, 0)]
    [InlineData("missing.child.example.", 1, 3)]
    public async Task NegativeUsesContainingZoneSoaAndAuthenticatedNsec(string name, int type, int code)
    {
        using var fixture = new OnlineDnssecFixture();
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse(name), (ushort)type, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(code, result.ResponseCode);
        Assert.Empty(result.Answers);
        Assert.Equal(6, Assert.Single(result.Authority).Type);
        Assert.Equal(result.Origin, result.Authority[0].Owner);
        Assert.True(result.AuthenticatedTtl <= result.Authority[0].GetSoaMinimum());
    }

    [Fact]
    public async Task ParentSideDsDoesNotDescendOrUseChildApexKeys()
    {
        using var fixture = new OnlineDnssecFixture();
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(fixture.Child, 43, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(fixture.Root, result.Origin);
        Assert.Equal(43, Assert.Single(result.Answers).Type);
        Assert.All(fixture.Calls, call => Assert.Equal(OnlineDnssecFixture.RootServer, call.Server));
    }

    [Fact]
    public async Task UnsignedDelegationReturnsOnlyAuthenticatedMarker()
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.UnsignedDelegation, result.Outcome);
        Assert.Equal(fixture.Child, result.UnsignedDelegation);
        Assert.Equal(fixture.Root, result.Origin);
        Assert.Equal(2, result.ResponseCode);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
        Assert.Equal(3, fixture.Calls.Count);
        Assert.All(fixture.Calls, call => Assert.Equal(OnlineDnssecFixture.RootServer, call.Server));
    }

    [Fact]
    public async Task ExplicitDsAbsenceIsAuthenticatedParentNodata()
    {
        using var fixture = new OnlineDnssecFixture { UnsignedChild = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(fixture.Child, 43, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(0, result.ResponseCode);
        Assert.Equal(fixture.Root, result.Origin);
        Assert.Equal(6, Assert.Single(result.Authority).Type);
    }

    [Fact]
    public async Task ObservedAdAndDoDoNotAuthorizeOrPreventAuthenticData()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, flags: (ushort)(reply.Flags & ~0x20), ednsFlags: 0);
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
    }

    [Fact]
    public async Task OutputCollectionsAreOwnedAndCannotBeChanged()
    {
        using var fixture = new OnlineDnssecFixture();
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.example."), 1, 1), CancellationToken.None);
        fixture.RootRecords.Clear();
        Assert.Single(result.Answers);
        Assert.Throws<NotSupportedException>(() => ((IList<DnsRecord>)result.Answers).Clear());
        Assert.False(typeof(IDnsResolver).IsAssignableFrom(typeof(DnssecIterativeResolver)));
        Assert.False(typeof(DnsAnswer).IsAssignableFrom(typeof(DnssecResolutionResult)));
    }

    [Fact]
    public async Task ZeroTtlDataCanAuthenticateWithoutCacheLease()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.RootRecords[0] = fixture.RootRecords[0].WithTtl(0);
        var result = await fixture.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(0U, result.AuthenticatedTtl);
        Assert.Equal(0U, Assert.Single(result.Answers).Ttl);
    }
}
