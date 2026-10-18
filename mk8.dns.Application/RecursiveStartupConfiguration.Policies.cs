using System.Text.Json;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.Application;

internal sealed partial record RecursiveStartupConfiguration
{
    private static DnssecTrustEpochPolicy ValidationPolicy(JsonElement values, int maximumRequests)
    {
        // Omitted optional objects retain the library's existing policy. A
        // supplied object is closed and complete; no partial setting fallback.
        var defaults = new DnssecTrustEpochPolicy(maximumActiveRequests: maximumRequests);
        var entries = defaults.MaximumEntries;
        var bytes = defaults.MaximumPayloadBytes;
        var positive = defaults.MaximumPositiveTtl;
        var negative = defaults.MaximumNegativeTtl;
        if (values.TryGetProperty("cachePolicy", out var cache))
        {
            RequireFields(cache, ["maximumEntries", "maximumPayloadBytes", "maximumPositiveTtl", "maximumNegativeTtl"]);
            entries = (int)Number(cache, "maximumEntries", 1, 65536);
            bytes = Number(cache, "maximumPayloadBytes", 1, 536870912);
            positive = (uint)Number(cache, "maximumPositiveTtl", 1, 604800);
            negative = (uint)Number(cache, "maximumNegativeTtl", 1, 86400);
        }
        var exchanges = defaults.MaximumExchanges;
        var aliases = defaults.MaximumAliasHops;
        var verification = defaults.MaximumVerificationAttempts;
        if (values.TryGetProperty("iterationPolicy", out var iteration))
        {
            RequireFields(iteration, ["maximumExchanges", "maximumAliasHops", "maximumVerificationAttempts"]);
            exchanges = (int)Number(iteration, "maximumExchanges", 1, 256);
            aliases = (int)Number(iteration, "maximumAliasHops", 1, 32);
            verification = (int)Number(iteration, "maximumVerificationAttempts", 1, 4096);
        }
        DnsQnameMinimisationPolicy? minimisation = null;
        if (values.TryGetProperty("qnameMinimisation", out var discovery))
        {
            RequireFields(discovery, ["maximumSteps"]);
            minimisation = new DnsQnameMinimisationPolicy((int)Number(discovery, "maximumSteps", 1, 128));
        }
        // The constructor also enforces negative <= positive TTL. Client-proof
        // epochs deliberately do not compose the separate failure cache.
        return new DnssecTrustEpochPolicy(maximumRequests, entries, bytes, positive, negative,
            exchanges, aliases, verification, failureCache: null, minimisation);
    }
}
