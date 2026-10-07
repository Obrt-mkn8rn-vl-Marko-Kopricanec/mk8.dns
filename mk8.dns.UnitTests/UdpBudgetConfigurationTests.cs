using Mk8.Dns.Configuration;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class UdpBudgetConfigurationTests
{
    public static TheoryData<string, int, int> Limits => new()
    {
        { "--udp-response-rate", 1, 1_000_000 }, { "--udp-response-burst", 1, 1_000_000 },
        { "--udp-byte-rate", 1, 1_000_000_000 }, { "--udp-byte-burst", 512, 1_000_000_000 },
        { "--udp-global-response-rate", 1, 1_000_000 }, { "--udp-global-response-burst", 1, 1_000_000 },
        { "--udp-global-byte-rate", 1, 1_000_000_000 }, { "--udp-global-byte-burst", 512, 1_000_000_000 },
        { "--udp-prefix-limit", 1, 65_536 },
    };

    [Fact]
    public void DefaultsAndExplicitProfileMapToTheConcreteBudget()
    {
        var settings = Parse("authoritative-replica"); var limits = settings.UdpResponseLimits;
        Assert.Equal(new UdpResponseBudgetSettings(), limits);
        var limiter = new DnsResponseLimiter(new BudgetClock(), limits.ResponsesPerSecond, limits.ResponseBurst, limits.BytesPerSecond, limits.ByteBurst,
            limits.GlobalResponsesPerSecond, limits.GlobalResponseBurst, limits.GlobalBytesPerSecond, limits.GlobalByteBurst, limits.MaximumPrefixes);
        for (var i = 0; i < 200; i++) Assert.True(limiter.TryAdmit(new byte[4], 12));
        Assert.False(limiter.TryAdmit(new byte[4], 12));
    }

    [Theory]
    [MemberData(nameof(Limits))]
    public void EachBudgetHasExplicitBoundsAndIsReplicaOnly(string flag, int minimum, int maximum)
    {
        _ = Parse("authoritative-replica", flag, minimum.ToString(System.Globalization.CultureInfo.InvariantCulture));
        _ = Parse("authoritative-replica", flag, maximum.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Throws<ArgumentException>(() => Parse("controller", flag, minimum.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        foreach (var value in new[] { (minimum - 1).ToString(System.Globalization.CultureInfo.InvariantCulture), (maximum + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), "-1", "+1", " 1", "1 ", "1,000", "1.0", "2147483648" })
            Assert.Throws<ArgumentException>(() => Parse("authoritative-replica", flag, value));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    public void ConcreteBudgetsRejectInvalidOverridesBeforeUse(int field)
    {
        var values = new[] { 100, 200, 51200, 102400, 10000, 20000, 5120000, 10240000, 4096 };
        values[field] = 0;
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnsResponseLimiter(new BudgetClock(), values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8]));
    }

    private static ApplicationSettings Parse(string role, params string[] args) => ApplicationSettings.Parse(["--socket", "/tmp/budget/app.sock", "--state", "/tmp/budget/state", "--node", "budget", "--role", role, .. args]);
}
