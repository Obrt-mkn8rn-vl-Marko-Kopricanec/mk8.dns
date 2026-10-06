using System.Text.Json.Serialization;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Operator;

[JsonSourceGenerationOptions(UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(ManagementRequest))]
[JsonSerializable(typeof(ManagementReply))]
internal sealed partial class OperatorJsonContext : JsonSerializerContext;
