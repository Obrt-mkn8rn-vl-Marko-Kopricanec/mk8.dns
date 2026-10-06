using System.Text.Json.Serialization;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

[JsonSourceGenerationOptions(UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, RespectRequiredConstructorParameters = true, MaxDepth = 32)]
[JsonSerializable(typeof(ManagementApiRequest))]
[JsonSerializable(typeof(ManagementReply))]
[JsonSerializable(typeof(ManagementHttpError))]
internal sealed partial class ManagementHttpJsonContext : JsonSerializerContext;
