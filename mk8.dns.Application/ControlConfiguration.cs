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

internal sealed record ControlConfiguration([property: JsonRequired] Guid Epoch, [property: JsonRequired] string TargetNode, [property: JsonRequired] ZoneScope[] Zones, [property: JsonRequired] string KeySecret, [property: JsonRequired] string? ConnectionStringSecret, [property: JsonRequired] string? PublicationSocket, [property: JsonRequired] GrantConfiguration[]? Grants, [property: JsonRequired] uint SigningScanSeconds, [property: JsonRequired] uint DispatchIntervalMilliseconds);
