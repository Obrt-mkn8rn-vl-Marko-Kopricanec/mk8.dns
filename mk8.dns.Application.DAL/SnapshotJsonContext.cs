using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mk8.Dns.Application.DAL;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, RespectRequiredConstructorParameters = true, MaxDepth = 8)]
[JsonSerializable(typeof(SnapshotDocument))]
[JsonSerializable(typeof(ActiveDocument))]
internal sealed partial class SnapshotJsonContext : JsonSerializerContext;
