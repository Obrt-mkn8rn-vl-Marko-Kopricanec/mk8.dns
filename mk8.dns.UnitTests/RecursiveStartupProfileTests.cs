using System.Text.Json.Nodes;
using Mk8.Dns.Application;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecursiveStartupProfileTests
{
    [Theory]
    [InlineData("recursive", false, false)]
    [InlineData("recursive-refresh", true, false)]
    [InlineData("recursive-checking-disabled", false, true)]
    [InlineData("recursive-refresh-checking-disabled", true, true)]
    public async Task ExplicitProfilesComposeOnlyTheirRequiredPolicies(string mode, bool refresh, bool checkingDisabled)
    {
        using var fixture = new RecursiveStartupConfigurationFixture();
        var snapshot = await fixture.LoadAsync(mode, fixture.Configuration(refresh, checkingDisabled).ToJsonString()).ConfigureAwait(true);
        var settings = RecursiveStartupConfiguration.FromSecrets(snapshot, mode);
        Assert.Equal(refresh, settings.RefreshPolicy is not null);
        Assert.Equal(checkingDisabled, settings.CheckingDisabledDnssecMaterial is not null);
        Assert.Null(settings.EpochPolicy.Minimisation);
        Assert.Null(settings.EpochPolicy.FailureCache);
        Assert.Equal(4096, settings.EpochPolicy.MaximumEntries);
        Assert.Equal(16777216L, settings.EpochPolicy.MaximumPayloadBytes);
        Assert.Equal(86400U, settings.EpochPolicy.MaximumPositiveTtl);
        Assert.Equal(3600U, settings.EpochPolicy.MaximumNegativeTtl);
        Assert.Equal(64, settings.EpochPolicy.MaximumExchanges);
        Assert.Equal(16, settings.EpochPolicy.MaximumAliasHops);
        Assert.Equal(512, settings.EpochPolicy.MaximumVerificationAttempts);
        if (checkingDisabled) Assert.True(settings.CheckingDisabledDnssecMaterial);
        Assert.Equal("MissingAnchorKey", settings.KeySecret);
        Assert.False(Directory.Exists(settings.StoreDirectory));
    }

    [Theory]
    [InlineData("recursive", false, false, 1)]
    [InlineData("recursive-refresh", true, false, 128)]
    [InlineData("recursive-checking-disabled", false, true, 128)]
    [InlineData("recursive-refresh-checking-disabled", true, true, 1)]
    public async Task EveryProfileCanExplicitlySelectBoundedQnameMinimisation(string mode, bool refresh, bool checkingDisabled, int steps)
    {
        using var fixture = new RecursiveStartupConfigurationFixture();
        var input = fixture.Configuration(refresh, checkingDisabled);
        input["qnameMinimisation"] = new JsonObject { ["maximumSteps"] = steps };
        var snapshot = await fixture.LoadAsync(mode, input.ToJsonString()).ConfigureAwait(true);
        var settings = RecursiveStartupConfiguration.FromSecrets(snapshot, mode);
        Assert.NotNull(settings.EpochPolicy.Minimisation);
        Assert.Equal(steps, settings.EpochPolicy.Minimisation.MaximumSteps);
        Assert.False(Directory.Exists(settings.StoreDirectory));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("{\"maximumSteps\":0}")]
    [InlineData("{\"maximumSteps\":129}")]
    [InlineData("{\"maximumSteps\":\"PROTECTED_VALUE\"}")]
    [InlineData("{\"maximumSteps\":1,\"maximumSteps\":2}")]
    [InlineData("{\"maximumSteps\":1,\"PROTECTED_VALUE\":true}")]
    public async Task InvalidMinimisationPolicyRefusesBeforeKeyOrStoreUse(string policy)
    {
        const string mode = "recursive";
        using var fixture = new RecursiveStartupConfigurationFixture();
        var input = fixture.Configuration(refresh: false, checkingDisabled: false).ToJsonString();
        var snapshot = await fixture.LoadAsync(mode, input[..^1] + ",\"qnameMinimisation\":" + policy + "}").ConfigureAwait(true);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => RecursiveStartup.RunAsync(snapshot, mode)).ConfigureAwait(true);
        Assert.DoesNotContain("PROTECTED_VALUE", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("MissingAnchorKey", error.Message, StringComparison.Ordinal);
        Assert.Null(error.InnerException);
        Assert.False(Directory.Exists(fixture.StoreDirectory));
    }

    [Theory]
    [InlineData("recursive-refresh-checking-disabled", "refreshPolicy")]
    [InlineData("recursive-refresh-checking-disabled", "checkingDisabledDnssecMaterial")]
    [InlineData("recursive-refresh", "checkingDisabledDnssecMaterial")]
    [InlineData("recursive-checking-disabled", "refreshPolicy")]
    public async Task CombinedPolicyIsRequiredAndOlderProfilesStillRefuseExtraFields(string mode, string field)
    {
        using var fixture = new RecursiveStartupConfigurationFixture();
        var input = fixture.Configuration(refresh: true, checkingDisabled: true);
        if (string.Equals(mode, "recursive-refresh-checking-disabled", StringComparison.Ordinal)) Assert.True(input.Remove(field));
        var snapshot = await fixture.LoadAsync(mode, input.ToJsonString()).ConfigureAwait(true);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => RecursiveStartup.RunAsync(snapshot, mode)).ConfigureAwait(true);
        Assert.DoesNotContain("MissingAnchorKey", error.Message, StringComparison.Ordinal);
        Assert.Null(error.InnerException);
        Assert.False(Directory.Exists(fixture.StoreDirectory));
    }

    [Theory]
    [InlineData("json")]
    [InlineData("root")]
    [InlineData("boolean")]
    [InlineData("number")]
    [InlineData("path")]
    [InlineData("identity")]
    public async Task MalformedProtectedSchemaHasOneValueFreeRefusalBeforeKeyOrStoreUse(string defect)
    {
        const string sentinel = "CONFIDENTIAL_SCHEMA_SENTINEL";
        const string mode = "recursive-refresh-checking-disabled";
        using var fixture = new RecursiveStartupConfigurationFixture();
        var input = fixture.Configuration(refresh: true, checkingDisabled: true);
        switch (defect)
        {
            case "boolean": input["checkingDisabledDnssecMaterial"] = sentinel; break;
            case "number": input["minimumRevision"] = JsonNode.Parse("1e9999"); break;
            case "path": input["storeDirectory"] = "/" + sentinel + "\0"; break;
            case "identity": input["storeIdentity"] = sentinel; break;
        }
        var text = defect switch
        {
            "json" => "{\"" + sentinel + "\":not-json}",
            "root" => "\"" + sentinel + "\"",
            _ => input.ToJsonString(),
        };
        var snapshot = await fixture.LoadAsync(mode, text).ConfigureAwait(true);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => RecursiveStartup.RunAsync(snapshot, mode)).ConfigureAwait(true);
        Assert.Equal("SecretRecursiveInvalid", error.Message);
        Assert.Null(error.InnerException);
        Assert.DoesNotContain(sentinel, error.ToString(), StringComparison.Ordinal);
        Assert.False(Directory.Exists(fixture.StoreDirectory));
    }

    [Fact]
    public async Task RetryIntervalCannotExceedRefreshIntervalInTheCombinedProfile()
    {
        const string mode = "recursive-refresh-checking-disabled";
        using var fixture = new RecursiveStartupConfigurationFixture();
        var input = fixture.Configuration(refresh: true, checkingDisabled: true);
        var refresh = Assert.IsType<JsonObject>(input["refreshPolicy"]);
        refresh["retryIntervalSeconds"] = 7200;
        var snapshot = await fixture.LoadAsync(mode, input.ToJsonString()).ConfigureAwait(true);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => RecursiveStartup.RunAsync(snapshot, mode)).ConfigureAwait(true);
        Assert.Equal("SecretRecursiveRetryIntervalBounds", error.Message);
        Assert.Null(error.InnerException);
        Assert.False(Directory.Exists(fixture.StoreDirectory));
    }
}
