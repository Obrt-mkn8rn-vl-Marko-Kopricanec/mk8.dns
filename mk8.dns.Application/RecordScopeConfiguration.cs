using System.Text.Json.Serialization;

namespace Mk8.Dns.Application;

internal sealed record RecordScopeConfiguration([property: JsonRequired] string Owner, [property: JsonRequired] ushort Type);
