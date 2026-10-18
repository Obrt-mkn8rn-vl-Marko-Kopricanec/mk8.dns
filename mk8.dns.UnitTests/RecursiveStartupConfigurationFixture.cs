using System.Text.Json.Nodes;
using Mk8.Dns.Configuration;
using Supprocom.Secrets;

namespace Mk8.Dns.UnitTests;

internal sealed class RecursiveStartupConfigurationFixture : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "m8-recursive-profile-" + Guid.NewGuid().ToString("N"));
    internal string StoreDirectory => Path.Combine(root, "unopened-journal");
    internal RecursiveStartupConfigurationFixture() => Directory.CreateDirectory(root);

    internal async Task<DnsServiceSecrets> LoadAsync(string mode, string input)
    {
        var document = SupprocomSecretDocument.Serialize([
            new SupprocomSecretSetting("Application:Mode", mode), new SupprocomSecretSetting("Application:Recursive", input),
        ]);
        await File.WriteAllTextAsync(Path.Combine(root, ".env"), document, CancellationToken.None).ConfigureAwait(false);
        return await DnsServiceSecrets.LoadDirectoryAsync("Application", root, CancellationToken.None).ConfigureAwait(false);
    }

    internal JsonObject Configuration(bool refresh, bool checkingDisabled)
    {
        var input = new JsonObject
        {
            ["storeDirectory"] = StoreDirectory,
            ["keySecret"] = "MissingAnchorKey",
            ["storeIdentity"] = "8fcad246be894cd0a6e825e046ba6d95",
            ["origin"] = ".",
            ["minimumRevision"] = 1,
            ["retention"] = false,
            ["listen"] = new JsonObject { ["address"] = "127.0.0.1", ["port"] = 5300 },
            ["roots"] = new JsonArray(new JsonObject { ["address"] = "127.0.0.1", ["port"] = 53 }),
            ["refreshServer"] = new JsonObject { ["address"] = "127.0.0.1", ["port"] = 53 },
            ["clientNetworks"] = new JsonArray(new JsonObject { ["address"] = "127.0.0.1", ["prefix"] = 32 }),
            ["allowAuthenticatedData"] = true,
            ["egressNetworks"] = new JsonArray(new JsonObject { ["address"] = "127.0.0.1", ["prefix"] = 32 }),
            ["authorityPort"] = 53,
            ["maximumRequests"] = 4,
            ["udpWorkers"] = 1,
            ["maximumTcpConnections"] = 2,
            ["maximumTcpMessages"] = 4,
            ["maximumWorkers"] = 2,
            ["maximumWaiters"] = 4,
            ["resolutionTimeoutMilliseconds"] = 1000,
            ["upstreamTimeoutMilliseconds"] = 500,
        };
        if (refresh)
        {
            input["refreshPolicy"] = new JsonObject
            {
                ["refreshIntervalSeconds"] = 3600,
                ["retryIntervalSeconds"] = 3600,
                ["maximumAttempts"] = 1,
            };
        }
        if (checkingDisabled) input["checkingDisabledDnssecMaterial"] = true;
        return input;
    }

    public void Dispose() => Directory.Delete(root, recursive: true);
}
