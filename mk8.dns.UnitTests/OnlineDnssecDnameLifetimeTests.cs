using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecDnameLifetimeTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(300)]
    [InlineData(900)]
    public async Task SyntheticCnameLifetimeCannotExceedSignedDnameOrReceivedCopy(int ttl)
    {
        using var fixture = new OnlineDnssecDnameFixture { CnameTtl = (uint)ttl };
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(5), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.Equal((uint)Math.Min(ttl, 300), result.Answers[1].Ttl);
        Assert.Equal((uint)Math.Min(ttl, 300), result.AuthenticatedTtl);
    }

    [Fact]
    public async Task DnameAndSyntheticCnameAgeAcrossAwaitedTargetWork()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Transform = reply => { if (reply.Question.Name.Equals(DnsName.Parse("www.example."))) fixture.Zones.Clock.Advance(5); return reply; };
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome);
        Assert.All(result.Answers, record => Assert.Equal(295U, record.Ttl));
        Assert.Equal(295U, result.AuthenticatedTtl);
    }

    [Fact]
    public async Task EarlierDnameExpiryDuringTargetWorkDiscardsWholeChain()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Supplied = [fixture.Dname, fixture.Zones.Sign([fixture.Dname], window: new DnssecSignatureWindow(100, 101))];
        fixture.Transform = reply => { if (reply.Question.Name.Equals(DnsName.Parse("www.example."))) fixture.Zones.Clock.Advance(2); return reply; };
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }

    [Fact]
    public async Task FinalProviderWorkCannotExpireEarlierDnameWithoutRefusal()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Supplied = [fixture.Dname, fixture.Zones.Sign([fixture.Dname], window: new DnssecSignatureWindow(100, 103))];
        var calls = 0;
        var verifier = new DnssecChainFixture.CountingVerifier { AfterVerify = () => { if (++calls == 5) fixture.Zones.Clock.Advance(4); } };
        var result = await fixture.Zones.Resolver(verifier: verifier).ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(5, verifier.Calls);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task MixedCnameDnameCyclesAndHopExhaustionDiscardAllData(int kind)
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Zones.RootRecords.Clear();
        fixture.Zones.RootRecords.Add(new DnsRecord(DnsName.Parse("www.example."), 5, 300,
            DnsName.Parse(kind == 1 ? "www.branch.example." : "next.example.").ToWire()));
        var result = await fixture.Zones.Resolver(aliases: kind == 1 ? 16 : 1).ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Equal(3, fixture.Zones.Calls.Count);
    }

    [Fact]
    public async Task SelfRedirectingDnameIsBoundedAndDiscardsSyntheticData()
    {
        using var fixture = new OnlineDnssecDnameFixture();
        fixture.Dname = new DnsRecord(fixture.Dname.Owner, 39, 300, fixture.Dname.GetOwnerWire());
        var result = await fixture.Zones.Resolver().ResolveDnssecAsync(OnlineDnssecDnameFixture.Question(), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Equal(2, fixture.Zones.Calls.Count);
    }
}
