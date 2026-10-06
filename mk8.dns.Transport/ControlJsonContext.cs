using System.Text.Json.Serialization;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

[JsonSourceGenerationOptions(UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(ManagementRequest))]
[JsonSerializable(typeof(ManagementReply))]
[JsonSerializable(typeof(PublicationRequest))]
[JsonSerializable(typeof(PublicationReply))]
internal sealed partial class ControlJsonContext : JsonSerializerContext;
