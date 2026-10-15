using System.Security.Cryptography;
using System.Text.Json;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Operator;
using Mk8.Dns.Transport;

if (args.Length != 0) throw new ArgumentException("ServiceArgumentsForbidden", nameof(args));
var secrets = await DnsServiceSecrets.LoadAsync("Operator", CancellationToken.None).ConfigureAwait(false);
var settings = secrets.Arguments("Settings");
if (settings.Length != 6 || settings[0] is not ("--socket" or "--gateway-socket")
    || settings[2] is not "--request-secret" || settings[4] is not "--credential-secret" || !Path.IsPathFullyQualified(settings[1]))
{
    throw new InvalidDataException("SecretOperatorSettingsInvalid");
}

DnsServiceSecrets.ValidateName(settings[3]); DnsServiceSecrets.ValidateName(settings[5]);
secrets.RequireOnly(["Settings", settings[3], settings[5]]);
ManagementRequest? request = null;
try { request = JsonSerializer.Deserialize(secrets.JsonText(settings[3], ControlHostingExtensions.MaximumManagementBytes), OperatorJsonContext.Default.ManagementRequest); }
catch (JsonException) { /* Typed JSON paths and member names may themselves be confidential. */ }
if (request is null) throw new InvalidDataException("SecretManagementRequestInvalid");
var credential = secrets.Bytes(settings[5], 32);
try
{
    if (credential.Length != 32) throw new InvalidDataException("SecretCredentialLengthInvalid");
    using IDisposable lifetime = settings[0] is "--gateway-socket" ? new UnixManagementHttpClient(settings[1]) : new UnixControlClient(settings[1]);
    var client = (IZoneManagement)lifetime;
    var reply = await client.ExecuteAsync(request with { Credential = credential }, CancellationToken.None).ConfigureAwait(false);
    Console.WriteLine(JsonSerializer.Serialize(reply, OperatorJsonContext.Default.ManagementReply));
}
finally { CryptographicOperations.ZeroMemory(credential); }
