using System.Text.Json.Nodes;
using Mk8.Dns.Application;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecursiveStartupBudgetTests
{
    [Theory]
    [InlineData("recursive", false, false)]
    [InlineData("recursive-refresh", true, false)]
    [InlineData("recursive-checking-disabled", false, true)]
    [InlineData("recursive-refresh-checking-disabled", true, true)]
    public async Task ExplicitBudgetsComposeWithDiscoveryInEveryProfile(string mode, bool refresh, bool checkingDisabled)
    {
        using var fixture = new RecursiveStartupConfigurationFixture();
        var input = fixture.Configuration(refresh, checkingDisabled);
        input["cachePolicy"] = Cache();
        input["iterationPolicy"] = Iteration();
        input["qnameMinimisation"] = new JsonObject { ["maximumSteps"] = 32 };
        var secrets = await fixture.LoadAsync(mode, input.ToJsonString()).ConfigureAwait(true);
        var settings = RecursiveStartupConfiguration.FromSecrets(secrets, mode);
        var policy = settings.EpochPolicy;
        Assert.Equal(4, policy.MaximumActiveRequests);
        Assert.Equal(settings.MaximumRequests, policy.MaximumActiveRequests);
        Assert.Equal(3, policy.MaximumEntries);
        Assert.Equal(12345L, policy.MaximumPayloadBytes);
        Assert.Equal(120U, policy.MaximumPositiveTtl);
        Assert.Equal(30U, policy.MaximumNegativeTtl);
        Assert.Equal(7, policy.MaximumExchanges);
        Assert.Equal(3, policy.MaximumAliasHops);
        Assert.Equal(99, policy.MaximumVerificationAttempts);
        Assert.NotNull(policy.Minimisation);
        Assert.Equal(32, policy.Minimisation.MaximumSteps);
        Assert.Null(policy.FailureCache);
        Assert.False(Directory.Exists(fixture.StoreDirectory));
    }

    [Theory]
    [InlineData("cachePolicy", "maximumEntries", 0)]
    [InlineData("cachePolicy", "maximumPayloadBytes", 536870913)]
    [InlineData("cachePolicy", "maximumPositiveTtl", 0)]
    [InlineData("cachePolicy", "maximumNegativeTtl", 121)]
    [InlineData("iterationPolicy", "maximumExchanges", 257)]
    [InlineData("iterationPolicy", "maximumAliasHops", 33)]
    [InlineData("iterationPolicy", "maximumVerificationAttempts", 4097)]
    public async Task InvalidBudgetRefusesBeforeKeyOrStoreUse(string section, string field, long value)
    {
        using var fixture = new RecursiveStartupConfigurationFixture();
        var input = fixture.Configuration(refresh: false, checkingDisabled: false);
        var policy = string.Equals(section, "cachePolicy", StringComparison.Ordinal) ? Cache() : Iteration();
        policy[field] = value;
        input[section] = policy;
        await AssertRefusalAsync(fixture, input).ConfigureAwait(true);
    }

    [Theory]
    [InlineData("cachePolicy", "null")]
    [InlineData("cachePolicy", "missing")]
    [InlineData("iterationPolicy", "type")]
    [InlineData("iterationPolicy", "unknown")]
    [InlineData("failureCachePolicy", "unknown")]
    public async Task SuppliedPolicyIsCompleteClosedAndCannotEnableFailureCaching(string section, string defect)
    {
        using var fixture = new RecursiveStartupConfigurationFixture();
        var input = fixture.Configuration(refresh: false, checkingDisabled: false);
        var policy = string.Equals(section, "cachePolicy", StringComparison.Ordinal) ? Cache() : Iteration();
        switch (defect)
        {
            case "missing": Assert.True(policy.Remove("maximumEntries")); break;
            case "type": policy["maximumExchanges"] = "PROTECTED_VALUE"; break;
            case "unknown": policy["PROTECTED_VALUE"] = true; break;
        }
        input[section] = string.Equals(defect, "null", StringComparison.Ordinal) ? null : policy;
        await AssertRefusalAsync(fixture, input).ConfigureAwait(true);
    }

    private static async Task AssertRefusalAsync(RecursiveStartupConfigurationFixture fixture, JsonObject input)
    {
        var snapshot = await fixture.LoadAsync("recursive", input.ToJsonString()).ConfigureAwait(true);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => RecursiveStartup.RunAsync(snapshot, "recursive")).ConfigureAwait(true);
        Assert.DoesNotContain("MissingAnchorKey", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("PROTECTED_VALUE", error.ToString(), StringComparison.Ordinal);
        Assert.Null(error.InnerException);
        Assert.False(Directory.Exists(fixture.StoreDirectory));
    }

    private static JsonObject Cache() => new()
    {
        ["maximumEntries"] = 3,
        ["maximumPayloadBytes"] = 12345,
        ["maximumPositiveTtl"] = 120,
        ["maximumNegativeTtl"] = 30,
    };

    private static JsonObject Iteration() => new()
    {
        ["maximumExchanges"] = 7,
        ["maximumAliasHops"] = 3,
        ["maximumVerificationAttempts"] = 99,
    };
}
