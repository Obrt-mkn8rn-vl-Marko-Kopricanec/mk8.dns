using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineNsec3ResolutionTests
{
    [Theory]
    [InlineData("missing.example.", 1, 3)]
    [InlineData("missing.empty.example.", 1, 3)]
    [InlineData("www.example.", 28, 0)]
    [InlineData("empty.example.", 1, 0)]
    [InlineData("missing.child.example.", 1, 3)]
    [InlineData("www.child.example.", 28, 0)]
    [InlineData("empty.child.example.", 1, 0)]
    public async Task RootAndAuthenticatedChildNsec3NegativesPreserveSelectedOrigin(string name, ushort type, ushort code)
    {
        ArgumentNullException.ThrowIfNull(name);
        using var fixture = new OnlineNsec3Fixture();
        var result = await fixture.Resolver().ResolveDnssecAsync(Question(name, type), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(code, result.ResponseCode); Assert.Empty(result.Answers);
        var soa = Assert.Single(result.Authority); Assert.Equal(6, soa.Type);
        Assert.Equal(DnsName.Parse(name.Contains("child", StringComparison.Ordinal) ? "child.example." : "example."), soa.Owner);
    }

    [Theory]
    [InlineData("new.example.", 1)]
    [InlineData("new.example.", 28)]
    [InlineData("new.child.example.", 1)]
    [InlineData("new.child.example.", 28)]
    public async Task Nsec3WildcardPositiveAndNoDataUseAuthenticatedOriginalOwner(string name, ushort type)
    {
        ArgumentNullException.ThrowIfNull(name);
        using var fixture = new OnlineNsec3Fixture { Wildcard = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question(name, type), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome); Assert.Equal(0, result.ResponseCode);
        if (type == 1) { Assert.Equal(DnsName.Parse(name), Assert.Single(result.Answers).Owner); Assert.Empty(result.Authority); }
        else { Assert.Empty(result.Answers); Assert.Equal(6, Assert.Single(result.Authority).Type); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExactAndOptOutParentProofsReturnOnlyUnsignedDelegation(bool optOut)
    {
        using var fixture = new OnlineNsec3Fixture { Unsigned = true, OptOut = optOut };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question("www.child.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.UnsignedDelegation, result.Outcome);
        Assert.Equal(DnsName.Parse("child.example."), result.UnsignedDelegation);
        Assert.Empty(result.Answers); Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
        Assert.Contains(fixture.Calls, call => call.Question.Equals(Question("child.example.", 43)) && call.Server.Equals(OnlineDnssecFixture.RootServer));
    }

    [Fact]
    public async Task OptOutCoverCannotAuthenticateOrdinaryNegativeOrWildcardData()
    {
        using var fixture = new OnlineNsec3Fixture { OptOut = true };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question("missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        fixture.Wildcard = true;
        result = await fixture.Resolver().ResolveDnssecAsync(Question("new.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome); Assert.Empty(result.Answers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CnameChaseRestartsAndAuthenticatedDenialOrUnsignedMarkerDiscardsInlineTarget(bool isUnsigned)
    {
        using var fixture = new OnlineNsec3Fixture { Unsigned = isUnsigned, OptOut = isUnsigned };
        var target = isUnsigned ? "www.child.example." : "missing.child.example.";
        fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("jump.example."), 5, 300, DnsName.Parse(target).ToWire()));
        fixture.Transform = reply => reply.Question.Name.Equals(DnsName.Parse("jump.example."))
            ? OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers, DnssecFixture.A(target, 99)]) : reply;
        var result = await fixture.Resolver().ResolveDnssecAsync(Question("jump.example."), CancellationToken.None);
        Assert.Equal(isUnsigned ? DnssecResolutionOutcome.UnsignedDelegation : DnssecResolutionOutcome.Authenticated, result.Outcome);
        if (isUnsigned) { Assert.Empty(result.Answers); Assert.Empty(result.Authority); }
        else { Assert.Equal(5, Assert.Single(result.Answers).Type); Assert.Equal(3, result.ResponseCode); Assert.Single(result.Authority); }
    }

    [Fact]
    public async Task SuppliedSaltIsUsedByOnlineProofValidation()
    {
        using var fixture = new OnlineNsec3Fixture { Salt = [1, 2, 3] };
        var result = await fixture.Resolver().ResolveDnssecAsync(Question("missing.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
    }

    internal static DnsQuestion Question(string name, ushort type = 1) => new(DnsName.Parse(name), type, 1);
}
