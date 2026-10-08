using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecDnameTests
{
    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 1)]
    [InlineData(false, 5)]
    [InlineData(true, 5)]
    public async Task AuthenticatedDnameDerivesCnameWithOrWithoutUnsignedUpstreamCopy(bool supplied, int type)
    {
        using var fixture = new OnlineDnssecDnameFixture { IncludeCname = supplied };
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question((ushort)type), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(0, result.ResponseCode);
        Assert.Equal(type == 5 ? 2 : 3, result.Answers.Count);
        Assert.Equal(39, result.Answers[0].Type);
        Assert.Equal(5, result.Answers[1].Type);
        Assert.Equal(DnsName.Parse("www.example."), result.Answers[1].GetTarget());
        Assert.Equal(result.Answers[0].Ttl, result.Answers[1].Ttl);
        Assert.Equal(type != 5, fixture.Zones.Calls.Any(call => call.Question.Name.Equals(DnsName.Parse("www.example."))));
    }

    [Theory]
    [InlineData("missing.branch.example.", 1, 3)]
    [InlineData("www.branch.example.", 28, 0)]
    public async Task AuthenticatedDnameChainCanEndInAuthenticatedNegative(string name, int type, int code)
    {
        ArgumentNullException.ThrowIfNull(name);
        using var fixture = new OnlineDnssecDnameFixture();
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse(name), (ushort)type, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(code, result.ResponseCode);
        Assert.Equal(2, result.Answers.Count);
        Assert.Equal(6, Assert.Single(result.Authority).Type);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EveryActualTargetZoneAuthenticatesIndependently(bool childToParent)
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Dname = new DnsRecord(DnsName.Parse(childToParent ? "branch.child.example." : "branch.example."), 39, 300,
            DnsName.Parse(childToParent ? "example." : "child.example.").ToWire());
        var question = new DnsQuestion(fixture.Dname.Owner.PrependLabel("www"u8), 1, 1);
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(3, result.Answers.Count);
        Assert.Contains(fixture.Zones.Calls, call => call.Question.Type == 48 && call.Server.Equals(OnlineDnssecFixture.ChildServer));
        Assert.Equal(childToParent ? fixture.Zones.Root : fixture.Zones.Child, result.Origin);
    }

    [Theory]
    [InlineData(1, DnssecResolutionOutcome.Failure)]
    [InlineData(5, DnssecResolutionOutcome.Authenticated)]
    public async Task OutsideIslandTargetOnlyDescribedByExplicitCname(int type, DnssecResolutionOutcome expected)
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Dname = new DnsRecord(fixture.Dname.Owner, 39, 300, DnsName.Parse("other.").ToWire());
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question((ushort)type), CancellationToken.None);
        Assert.Equal(expected, result.Outcome);
        Assert.Equal(2, fixture.Zones.Calls.Count);
        if (expected == DnssecResolutionOutcome.Failure) Assert.Empty(result.Answers);
    }

    [Fact]
    public async Task UnsignedTargetMarkerDiscardsAuthenticatedAliasChain()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Zones.UnsignedChild = true;
        fixture.Dname = new DnsRecord(fixture.Dname.Owner, 39, 300, fixture.Zones.Child.ToWire());
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.UnsignedDelegation, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
        Assert.DoesNotContain(fixture.Zones.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer));
    }

    [Fact]
    public async Task InlineTargetDataCannotAuthorizeDnameTarget()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Transform = reply => reply.Question.Equals(OnlineDnssecDnameFixture.Question())
            ? OnlineDnssecFixture.Copy(reply, answers: [.. reply.Answers, DnssecFixture.A("www.example.", 99)]) : reply;
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(1, result.Answers[^1].GetData()[^1]);
        Assert.Contains(fixture.Zones.Calls, call => call.Question.Name.Equals(DnsName.Parse("www.example.")));
    }

    [Fact]
    public async Task InlineNxdomainDoesNotReplaceIndependentTargetAuthentication()
    {
        using var fixture = new OnlineDnssecDnameFixture { Code = 3 };
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(0, result.ResponseCode);
        Assert.Equal(1, result.Answers[^1].Type);
        Assert.Contains(fixture.Zones.Calls, call => call.Question.Name.Equals(DnsName.Parse("www.example.")));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(39)]
    public async Task DnameOwnerDoesNotRedirectItself(int type)
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Zones.RootRecords.Add(fixture.Dname);
        fixture.Zones.RootRecords.Add(DnssecFixture.A("branch.example."));
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(new DnsQuestion(fixture.Dname.Owner, (ushort)type, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal(type, Assert.Single(result.Answers).Type);
        Assert.Equal(2, fixture.Zones.Calls.Count);
    }
}
