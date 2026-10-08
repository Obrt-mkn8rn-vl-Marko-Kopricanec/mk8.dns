using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecDnameAdmissionTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task UnauthenticatedAmbiguousOrContradictoryDnameCannotAuthorizeSyntheticData(int defect)
    {
        using var fixture = new OnlineDnssecDnameFixture { IncludeCname = false };
        var dname = fixture.Dname;
        var signature = fixture.Zones.Sign([dname]);
        var bad = signature.GetData(); bad[^1] ^= 1;
        var cname = new DnsRecord(OnlineDnssecDnameFixture.Question().Name, 5, 300, DnsName.Parse("forged.example.").ToWire());
        fixture.Supplied = defect switch
        {
            0 => [dname],
            1 => [dname, new DnsRecord(signature.Owner, 46, signature.Ttl, bad)],
            2 => [new DnsRecord(dname.Owner, 39, 300, DnsName.Parse("changed.example.").ToWire()), signature],
            3 => [dname, signature, cname],
            4 => [dname, signature, DnssecFixture.A(OnlineDnssecDnameFixture.Question().Name.ToString())],
            5 => [dname, signature, new DnsRecord(dname.Owner, 39, 300, DnsName.Parse("other.example.").ToWire())],
            6 => [dname, signature, new DnsRecord(DnsName.Parse("example."), 39, 300, DnsName.Parse("elsewhere.").ToWire())],
            _ => [dname, fixture.Zones.Sign([dname.WithOwner(DnsName.Parse("branch.child.example."))], child: true).WithOwner(dname.Owner)],
        };
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Empty(result.Authority);
        Assert.Equal(2, fixture.Zones.Calls.Count);
    }

    [Fact]
    public async Task NonoverflowDnameCannotClaimYxdomain()
    {
        using var fixture = new OnlineDnssecDnameFixture { Code = 6 };
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }

    [Fact]
    public async Task DnameOutsideSelectedZoneCannotUseSelectedZoneSignature()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Dname = new DnsRecord(DnsName.Parse("example."), 39, 300, DnsName.Parse("other.").ToWire());
        fixture.Transform = reply => reply.Question.Name.Equals(DnsName.Parse("www.child.example."))
            && reply.Server.Equals(OnlineDnssecFixture.ChildServer)
            ? OnlineDnssecFixture.Reply(reply.Question, reply.Server, [fixture.Dname,
                fixture.Zones.Sign([fixture.Dname.WithOwner(fixture.Zones.Child)], child: true).WithOwner(fixture.Dname.Owner)]) : reply;
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(new DnsQuestion(DnsName.Parse("www.child.example."), 1, 1), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Contains(fixture.Zones.Calls, call => call.Server.Equals(OnlineDnssecFixture.ChildServer) && call.Question.Type == 1);
    }

    [Fact]
    public async Task WildcardExpandedDnameCannotAuthorizeSubtreeRedirection()
    {
        using var fixture = new OnlineDnssecDnameFixture { IncludeCname = false };
        var wildcard = new DnsRecord(DnsName.Parse("*.example."), 39, 300, fixture.Dname.GetData());
        fixture.Supplied = [fixture.Dname, fixture.Zones.Sign([wildcard]).WithOwner(fixture.Dname.Owner)];
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }

    [Theory]
    [InlineData(0, DnssecResolutionOutcome.Failure)]
    [InlineData(6, DnssecResolutionOutcome.Authenticated)]
    public async Task SignedYxdomainRequiresActualNameOverflow(int code, DnssecResolutionOutcome expected)
    {
        using var fixture = new OnlineDnssecDnameFixture { IncludeCname = false, Code = (ushort)code };
        var target = string.Join('.', Enumerable.Repeat(new string('a', 63), 3)) + "." + new string('b', 61) + ".";
        fixture.Dname = new DnsRecord(fixture.Dname.Owner, 39, 300, DnsName.Parse(target).ToWire());
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(expected, result.Outcome);
        if (expected == DnssecResolutionOutcome.Authenticated)
        {
            Assert.Equal(6, result.ResponseCode);
            Assert.Equal(39, Assert.Single(result.Answers).Type);
            Assert.Empty(result.Authority);
        }
        else Assert.Empty(result.Answers);
        Assert.Equal(2, fixture.Zones.Calls.Count);
    }

    [Fact]
    public async Task OverflowWithoutAuthenticatedDnameIsFailure()
    {
        using var fixture = new OnlineDnssecDnameFixture { Code = 6, IncludeCname = false };
        var target = string.Join('.', Enumerable.Repeat(new string('a', 63), 3)) + "." + new string('b', 61) + ".";
        fixture.Dname = new DnsRecord(fixture.Dname.Owner, 39, 300, DnsName.Parse(target).ToWire());
        fixture.Supplied = [fixture.Dname];
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }
}
