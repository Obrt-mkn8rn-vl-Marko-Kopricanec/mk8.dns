using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mk8.Dns.Configuration;

// Explicit installation settings may tighten these inherited software ceilings.
// They are not a measured resource or shutdown-progress guarantee.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ServiceHostPolicy(
    [property: JsonRequired] int ShutdownSeconds,
    [property: JsonRequired] int HeaderBytes,
    [property: JsonRequired] int HeaderCount,
    [property: JsonRequired] int RequestLineBytes,
    [property: JsonRequired] int HeaderTimeoutSeconds,
    [property: JsonRequired] int Connections,
    [property: JsonRequired] int ApplicationStreams,
    [property: JsonRequired] int PublicationStreams)
{
    public static ServiceHostPolicy FromSecrets(DnsServiceSecrets secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        ServiceHostPolicy? policy = null;
        try
        {
            policy = JsonSerializer.Deserialize<ServiceHostPolicy>(secrets.JsonText("HostPolicy"));
        }
        catch (JsonException) { /* Do not attach secret-input diagnostics to startup output. */ }
        if (policy is null) throw new InvalidDataException("SecretHostPolicyInvalid");
        if (policy.ShutdownSeconds is < 1 or > 30 || policy.HeaderBytes is < 256 or > 4096
            || policy.HeaderCount is < 1 or > 32 || policy.RequestLineBytes is < 256 or > 2048
            || policy.HeaderTimeoutSeconds is < 1 or > 5 || policy.Connections is < 1 or > 16
            || policy.ApplicationStreams is < 1 or > 16 || policy.PublicationStreams is < 1 or > 2)
        {
            throw new InvalidDataException("SecretHostPolicyBounds");
        }

        return policy;
    }
}
