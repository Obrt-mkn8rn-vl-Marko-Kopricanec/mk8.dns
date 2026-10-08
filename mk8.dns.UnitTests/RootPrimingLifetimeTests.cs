using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RootPrimingLifetimeTests
{
    [Fact]
    public async Task HintMinimumAndConservativeAgingFenceSnapshot()
    {
        using var fixture = new RootPrimingFixture(1);
        fixture.Addresses[0] = fixture.Addresses[0].WithTtl(7);
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(7U, result.RemainingTtl);
        fixture.Clock.Advance(0.1);
        Assert.Equal(6U, result.RemainingTtl);
        fixture.Clock.SetMonotonic(0);
        Assert.Equal(6U, result.RemainingTtl);
        fixture.Clock.Advance(8);
        Assert.Equal(0U, result.RemainingTtl);
        fixture.Clock.SetMonotonic(0); fixture.Clock.SetWall(100);
        Assert.Equal(0U, result.RemainingTtl);
    }

    [Theory]
    [InlineData(48)]
    [InlineData(2)]
    public async Task ReceivedKeyOrNsLifetimeCapsAddressSnapshot(int type)
    {
        using var fixture = new RootPrimingFixture();
        fixture.Transform = reply => reply.Question.Type == type
            ? OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Select(record => record.WithTtl(3)).ToArray()) : reply;
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(3U, result.RemainingTtl);
        if (type == 48) fixture.Clock.SetWall(103);
        else fixture.Clock.SetMonotonic(3);
        Assert.Equal(0U, result.RemainingTtl);
        fixture.Clock.SetWall(100); fixture.Clock.SetMonotonic(0);
        Assert.Equal(0U, result.RemainingTtl);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SelectedAndUnusedNsSignatureWindowsAreRetained(bool unused)
    {
        using var fixture = new RootPrimingFixture();
        fixture.Transform = reply => reply.Question.Type != 2 ? reply : OnlineDnssecFixture.Copy(reply, answers:
            [.. reply.Answers.Where(record => unused || record.Type != 46), fixture.Sign(fixture.NameServers, new DnssecSignatureWindow(100, 103))]);
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(3U, result.RemainingTtl);
        fixture.Clock.SetWall(104);
        Assert.Equal(0U, result.RemainingTtl);
        fixture.Clock.SetWall(100);
        Assert.Equal(0U, result.RemainingTtl);
    }

    [Fact]
    public async Task NetworkDelayIsChargedFromBeforeNsReceipt()
    {
        using var fixture = new RootPrimingFixture(1);
        fixture.Addresses[0] = fixture.Addresses[0].WithTtl(7);
        fixture.Transform = reply => { if (reply.Question.Type == 2) fixture.Clock.Advance(5); return reply; };
        var result = Assert.IsType<DnsRootPrimingResult>(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Equal(2U, result.RemainingTtl);
    }

    [Fact]
    public async Task AddressRepairCannotOutliveRootAuthentication()
    {
        using var fixture = new RootPrimingFixture(1) { Additional = [] };
        fixture.Transform = reply => { if (reply.Question.Type == 1) fixture.Clock.SetWall(10001); return reply; };
        Assert.Null(await fixture.Primer().PrimeAsync(CancellationToken.None));
        Assert.Contains(fixture.Calls, call => call.Question.Type == 1);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ZeroKeyNsOrAddressLeaseCannotProduceReusableHints(int kind)
    {
        using var fixture = new RootPrimingFixture(1);
        if (kind == 2)
            for (var index = 0; index < fixture.Addresses.Count; index++) fixture.Addresses[index] = fixture.Addresses[index].WithTtl(0);
        fixture.Transform = reply => reply.Question.Type == (kind == 0 ? 48 : kind == 1 ? 2 : 0)
            ? OnlineDnssecFixture.Copy(reply, answers: reply.Answers.Select(record => record.WithTtl(0)).ToArray()) : reply;
        Assert.Null(await fixture.Primer().PrimeAsync(CancellationToken.None));
    }
}
