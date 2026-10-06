using System.Text.Json;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Operator;
using Mk8.Dns.Transport;

if (args.Length != 6 || args[0] is not ("--socket" or "--gateway-socket") || !string.Equals(args[2], "--request", StringComparison.Ordinal) || !string.Equals(args[4], "--credential", StringComparison.Ordinal))
    throw new ArgumentException("Specify --socket or --gateway-socket, --request and --credential paths in that order.", nameof(args));
var request = JsonSerializer.Deserialize(PrivateFile.Read(args[3], ControlHostingExtensions.MaximumManagementBytes), OperatorJsonContext.Default.ManagementRequest)
    ?? throw new InvalidDataException("Management request is empty.");
var credential = PrivateFile.Read(args[5], 32);
if (credential.Length != 32)
    throw new InvalidDataException("An operator credential must contain exactly 32 random bytes.");
using IDisposable lifetime = args[0] is "--gateway-socket" ? new UnixManagementHttpClient(args[1]) : new UnixControlClient(args[1]);
var client = (IZoneManagement)lifetime;
var reply = await client.ExecuteAsync(request with { Credential = credential }, CancellationToken.None).ConfigureAwait(false);
Console.WriteLine(JsonSerializer.Serialize(reply, OperatorJsonContext.Default.ManagementReply));
