using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnsResponseLimiterTests
{
    private static readonly byte[] Peer = [192, 0, 2, 1];

    [Fact]
    public void AddressRotationInsideThePrefixCannotResetThePacketBudget()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, responseBurst: 2, responsesPerSecond: 2);
        Assert.True(limiter.TryAdmit(Peer, 12)); Assert.True(limiter.TryAdmit([192, 0, 2, 254], 12));
        Assert.False(limiter.TryAdmit([192, 0, 2, 42], 12));
        clock.Advance(TimeSpan.FromMilliseconds(250)); Assert.False(limiter.TryAdmit(Peer, 12));
        clock.Advance(TimeSpan.FromMilliseconds(250)); Assert.True(limiter.TryAdmit(Peer, 12));
        Assert.False(limiter.TryAdmit(Peer, 12)); Assert.Equal((3L, 3L, 1), limiter.Statistics);
    }

    [Fact]
    public void BytesAreChargedAtExactFinalLength()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, bytesPerSecond: 100, byteBurst: 512);
        Assert.True(limiter.TryAdmit(Peer, 400)); Assert.False(limiter.TryAdmit(Peer, 113));
        Assert.True(limiter.TryAdmit(Peer, 112)); Assert.False(limiter.TryAdmit(Peer, 12));
        clock.Advance(TimeSpan.FromMilliseconds(120)); Assert.True(limiter.TryAdmit(Peer, 12));
        Assert.False(limiter.TryAdmit(Peer, 12));
    }

    [Fact]
    public void NewPrefixesCannotResetTheGlobalPacketBudget()
    {
        var limiter = new DnsResponseLimiter(new BudgetClock(), globalResponseBurst: 2);
        Assert.True(limiter.TryAdmit(Peer, 12)); Assert.True(limiter.TryAdmit([192, 0, 3, 1], 12));
        Assert.False(limiter.TryAdmit([192, 0, 4, 1], 12)); Assert.Equal(3, limiter.Statistics.TrackedPrefixes);
    }

    [Fact]
    public void GlobalBytesApplyAcrossIpv4AndIpv6()
    {
        var limiter = new DnsResponseLimiter(new BudgetClock(), globalByteBurst: 512);
        Assert.True(limiter.TryAdmit(Peer, 400)); Assert.False(limiter.TryAdmit(new byte[16], 113));
        Assert.True(limiter.TryAdmit(new byte[16], 112)); Assert.False(limiter.TryAdmit([192, 0, 3, 1], 12));
    }

    [Fact]
    public void PrefixDenialsDoNotChargeTheGlobalBudget()
    {
        var limiter = new DnsResponseLimiter(new BudgetClock(), responseBurst: 1, globalResponseBurst: 2);
        Assert.True(limiter.TryAdmit(Peer, 12)); Assert.False(limiter.TryAdmit(Peer, 12));
        Assert.True(limiter.TryAdmit([192, 0, 3, 1], 12));
    }

    [Fact]
    public void GlobalDenialsDoNotChargeThePrefixBudget()
    {
        var clock = new BudgetClock();
        var limiter = new DnsResponseLimiter(clock, byteBurst: 512, bytesPerSecond: 1, globalResponsesPerSecond: 1, globalResponseBurst: 1);
        Assert.True(limiter.TryAdmit(Peer, 400)); Assert.False(limiter.TryAdmit([192, 0, 3, 1], 400));
        clock.Advance(TimeSpan.FromSeconds(1)); Assert.True(limiter.TryAdmit([192, 0, 3, 1], 400));
    }

    [Fact]
    public void UntrackedPrefixesShareOnePersistentOverflowBudget()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, responsesPerSecond: 1, responseBurst: 1, maximumPrefixes: 1);
        Assert.True(limiter.TryAdmit(Peer, 12)); Assert.True(limiter.TryAdmit([192, 0, 3, 1], 12));
        Assert.False(limiter.TryAdmit([192, 0, 4, 1], 12)); Assert.False(limiter.TryAdmit(Peer, 12));
        clock.Advance(TimeSpan.FromSeconds(1)); Assert.True(limiter.TryAdmit([192, 0, 5, 1], 12));
        Assert.False(limiter.TryAdmit([192, 0, 6, 1], 12)); Assert.Equal(1, limiter.Statistics.TrackedPrefixes);
    }

    [Fact]
    public void IdleReclamationCannotForgetLongerRefillDebt()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, responsesPerSecond: 1, responseBurst: 200, maximumPrefixes: 1);
        for (var i = 0; i < 200; i++) Assert.True(limiter.TryAdmit(Peer, 12));
        clock.Advance(TimeSpan.FromSeconds(60));
        for (var i = 0; i < 200; i++) Assert.True(limiter.TryAdmit([192, 0, 3, 1], 12));
        Assert.False(limiter.TryAdmit([192, 0, 4, 1], 12));
        clock.Advance(TimeSpan.FromSeconds(200)); Assert.True(limiter.TryAdmit([192, 0, 5, 1], 12));
        Assert.Equal(1, limiter.Statistics.TrackedPrefixes);
    }

    [Fact]
    public void LongByteRefillDebtAlsoPreventsPrematureReclamation()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, bytesPerSecond: 1, byteBurst: 512, maximumPrefixes: 1);
        Assert.True(limiter.TryAdmit(Peer, 512)); clock.Advance(TimeSpan.FromSeconds(60));
        Assert.True(limiter.TryAdmit([192, 0, 3, 1], 512)); Assert.False(limiter.TryAdmit([192, 0, 4, 1], 12));
    }

    [Fact]
    public void CleanupWorkIsBoundedAndIdleStateIsEventuallyReclaimed()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, maximumPrefixes: 130);
        for (var i = 0; i < 130; i++) Assert.True(limiter.TryAdmit([10, 0, (byte)i, 1], 12));
        clock.Advance(TimeSpan.FromSeconds(60));
        Assert.True(limiter.TryAdmit([11, 0, 1, 1], 12)); Assert.Equal(67, limiter.Statistics.TrackedPrefixes);
        Assert.True(limiter.TryAdmit([11, 0, 2, 1], 12)); Assert.Equal(4, limiter.Statistics.TrackedPrefixes);
        Assert.True(limiter.TryAdmit([11, 0, 3, 1], 12)); Assert.Equal(3, limiter.Statistics.TrackedPrefixes);
    }

    [Fact]
    public void WallClockChangesAndBackwardMonotonicSamplesMintNoCredit()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, responsesPerSecond: 1, responseBurst: 1);
        Assert.True(limiter.TryAdmit(Peer, 12)); clock.WallTime = DateTimeOffset.UnixEpoch.AddYears(100);
        Assert.False(limiter.TryAdmit(Peer, 12)); clock.Advance(TimeSpan.FromSeconds(-1)); Assert.False(limiter.TryAdmit(Peer, 12));
        clock.Advance(TimeSpan.FromSeconds(2)); Assert.True(limiter.TryAdmit(Peer, 12)); Assert.False(limiter.TryAdmit(Peer, 12));
    }

    [Fact]
    public void RefillAfterLongIdleNeverExceedsTheBurst()
    {
        var clock = new BudgetClock(); var limiter = new DnsResponseLimiter(clock, responseBurst: 2);
        Assert.True(limiter.TryAdmit(Peer, 12)); clock.Advance(TimeSpan.FromDays(1));
        Assert.True(limiter.TryAdmit(Peer, 12)); Assert.True(limiter.TryAdmit(Peer, 12)); Assert.False(limiter.TryAdmit(Peer, 12));
    }

    [Fact]
    public void MappedIpv4AndNativeIpv4ShareOneBudget()
    {
        var limiter = new DnsResponseLimiter(new BudgetClock(), responseBurst: 1);
        Assert.True(limiter.TryAdmit(Peer, 12));
        Assert.False(limiter.TryAdmit([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 254], 12));
        Assert.Equal(1, limiter.Statistics.TrackedPrefixes);
    }

    [Fact]
    public void Ipv6UsesFiftySixBitsAndFamiliesCannotCollide()
    {
        var limiter = new DnsResponseLimiter(new BudgetClock(), responseBurst: 1);
        var first = new byte[16]; first[0] = 0x20; first[1] = 1; first[7] = 1;
        Assert.True(limiter.TryAdmit(first, 12)); first[7] = 255; Assert.False(limiter.TryAdmit(first, 12));
        first[6] = 1; Assert.True(limiter.TryAdmit(first, 12));
        Assert.True(limiter.TryAdmit(Peer, 12)); Assert.True(limiter.TryAdmit([0, 0, 0, 0, 192, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1], 12));
    }

    [Fact]
    public async Task ConcurrentAdmissionsCannotOverspendEitherBudget()
    {
        var limiter = new DnsResponseLimiter(new BudgetClock(), responseBurst: 100, globalResponseBurst: 37);
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 200).Select(i => Task.Run(() => limiter.TryAdmit([10, 0, (byte)(i % 4), 1], 12)))).ConfigureAwait(true);
        Assert.Equal(37, outcomes.Count(allowed => allowed)); Assert.Equal((37L, 163L, 4), limiter.Statistics);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(15)]
    [InlineData(17)]
    public void WrongAddressKindsFailWithoutState(int length)
    {
        var limiter = new DnsResponseLimiter(new BudgetClock());
        Assert.Throws<ArgumentException>(() => limiter.TryAdmit(new byte[length], 12)); Assert.Equal((0L, 0L, 0), limiter.Statistics);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    [InlineData(65536)]
    public void ImpossibleResponseLengthsFailWithoutState(int length)
    {
        var limiter = new DnsResponseLimiter(new BudgetClock());
        Assert.Throws<ArgumentOutOfRangeException>(() => limiter.TryAdmit(Peer, length)); Assert.Equal((0L, 0L, 0), limiter.Statistics);
    }

    [Fact]
    public void NullClockIsRejected() => Assert.Throws<ArgumentNullException>(() => new DnsResponseLimiter(null!));
}
