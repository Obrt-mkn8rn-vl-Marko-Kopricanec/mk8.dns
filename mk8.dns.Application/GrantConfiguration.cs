using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Mk8.Dns.Application.BLL;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Configuration;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Infrastructure;
using Mk8.Dns.Transport;

namespace Mk8.Dns.Application;

internal sealed record GrantConfiguration([property: JsonRequired] Guid TenantId, [property: JsonRequired] Guid ZoneId, [property: JsonRequired] string Origin, [property: JsonRequired] string Actor, [property: JsonRequired] DateTimeOffset Expires, [property: JsonRequired] byte[] CredentialHash, [property: JsonRequired] string Profile = "zone", [property: JsonRequired] string[]? Actions = null, [property: JsonRequired] RecordScopeConfiguration[]? RecordScopes = null);
