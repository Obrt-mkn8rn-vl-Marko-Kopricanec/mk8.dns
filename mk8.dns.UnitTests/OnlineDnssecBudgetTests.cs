using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class OnlineDnssecBudgetTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task OneExchangeBudgetCoversAllKeyDelegationAndDataDependencies(int maximum)
    {
        using var fixture = new OnlineDnssecFixture();
        var result = await fixture.Resolver(exchanges: maximum).ResolveDnssecAsync(Question("www.child.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Equal(maximum, fixture.Calls.Count);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task CryptoAttemptBudgetIncludesBootstrapTransitionsAndFinalRechecks(int maximum)
    {
        using var fixture = new OnlineDnssecFixture();
        var verifier = new DnssecChainFixture.CountingVerifier();
        var result = await fixture.Resolver(attempts: maximum, verifier: verifier).ResolveDnssecAsync(Question("www.child.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.True(verifier.Calls <= maximum);
    }

    [Fact]
    public async Task AliasBudgetIsSharedAcrossResets()
    {
        using var fixture = Chain(3);
        var result = await fixture.Resolver(aliases: 2).ResolveDnssecAsync(Question("a0.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Equal(4, fixture.Calls.Count);
    }

    [Fact]
    public async Task AggregateRecordBudgetIncludesIrrelevantAdditionalData()
    {
        using var fixture = Chain(21);
        var additional = Enumerable.Range(0, 508).Select(index => new DnsRecord(DnsName.Parse("junk" + index + ".example."), 65000, 300, [1])).ToArray();
        fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, additional: additional);
        var result = await fixture.Resolver(aliases: 32).ResolveDnssecAsync(Question("a0.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.True(fixture.Calls.Count <= 17);
    }

    [Fact]
    public async Task AggregateExpandedByteBudgetBoundsOtherwiseSmallRecordCounts()
    {
        using var fixture = Chain(21);
        var additional = Enumerable.Range(0, 8).Select(index => new DnsRecord(DnsName.Parse("junk" + index + ".example."), 65000, 300, new byte[65535])).ToArray();
        fixture.Transform = reply => OnlineDnssecFixture.Copy(reply, additional: additional);
        var result = await fixture.Resolver(aliases: 32).ResolveDnssecAsync(Question("a0.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.True(fixture.Calls.Count <= 16);
    }

    [Fact]
    public async Task FinalOutputCannotExceedRecordBoundAfterAliasAccumulation()
    {
        using var fixture = Chain(16);
        fixture.RootRecords.AddRange(Enumerable.Range(0, 500).Select(index => new DnsRecord(DnsName.Parse("a16.example."), 1, 300,
            [192, 0, (byte)(index >> 8), (byte)index])));
        var result = await fixture.Resolver().ResolveDnssecAsync(Question("a0.example."), CancellationToken.None);
        Assert.Equal(DnssecResolutionOutcome.Failure, result.Outcome);
        Assert.Empty(result.Answers);
        Assert.Equal(18, fixture.Calls.Count);
    }

    private static DnsQuestion Question(string name) => new(DnsName.Parse(name), 1, 1);
    private static OnlineDnssecFixture Chain(int count)
    {
        var fixture = new OnlineDnssecFixture();
        for (var index = 0; index < count; index++)
            fixture.RootRecords.Add(new DnsRecord(DnsName.Parse("a" + index + ".example."), 5, 300, DnsName.Parse("a" + (index + 1) + ".example.").ToWire()));
        return fixture;
    }
}
