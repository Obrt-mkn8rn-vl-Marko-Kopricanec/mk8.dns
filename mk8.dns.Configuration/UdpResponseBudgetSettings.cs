using System.Globalization;

namespace Mk8.Dns.Configuration;

public sealed record UdpResponseBudgetSettings
{
    public int ResponsesPerSecond { get; init; } = 100;
    public int ResponseBurst { get; init; } = 200;
    public int BytesPerSecond { get; init; } = 51_200;
    public int ByteBurst { get; init; } = 102_400;
    public int GlobalResponsesPerSecond { get; init; } = 10_000;
    public int GlobalResponseBurst { get; init; } = 20_000;
    public int GlobalBytesPerSecond { get; init; } = 5_120_000;
    public int GlobalByteBurst { get; init; } = 10_240_000;
    public int MaximumPrefixes { get; init; } = 4096;

    internal static readonly string[] Arguments = ["--udp-response-rate", "--udp-response-burst", "--udp-byte-rate", "--udp-byte-burst",
        "--udp-global-response-rate", "--udp-global-response-burst", "--udp-global-byte-rate", "--udp-global-byte-burst", "--udp-prefix-limit"];

    internal static UdpResponseBudgetSettings Parse(Dictionary<string, string> values, string role)
    {
        if (!string.Equals(role, "authoritative-replica", StringComparison.Ordinal) && Arguments.Any(values.ContainsKey))
            throw new ArgumentException("Only an authoritative replica can configure UDP response budgets.", nameof(values));
        return new UdpResponseBudgetSettings
        {
            ResponsesPerSecond = Read(values, Arguments[0], 100, 1, 1_000_000),
            ResponseBurst = Read(values, Arguments[1], 200, 1, 1_000_000),
            BytesPerSecond = Read(values, Arguments[2], 51_200, 1, 1_000_000_000),
            ByteBurst = Read(values, Arguments[3], 102_400, 512, 1_000_000_000),
            GlobalResponsesPerSecond = Read(values, Arguments[4], 10_000, 1, 1_000_000),
            GlobalResponseBurst = Read(values, Arguments[5], 20_000, 1, 1_000_000),
            GlobalBytesPerSecond = Read(values, Arguments[6], 5_120_000, 1, 1_000_000_000),
            GlobalByteBurst = Read(values, Arguments[7], 10_240_000, 512, 1_000_000_000),
            MaximumPrefixes = Read(values, Arguments[8], 4096, 1, 65_536),
        };
    }

    private static int Read(Dictionary<string, string> values, string key, int fallback, int minimum, int maximum)
    {
        if (!values.TryGetValue(key, out var text))
            return fallback;
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < minimum || value > maximum)
            throw new ArgumentException("UDP response budget is outside its supported range.", nameof(values));
        return value;
    }
}
