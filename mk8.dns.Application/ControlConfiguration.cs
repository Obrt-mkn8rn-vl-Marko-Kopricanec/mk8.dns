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

internal sealed record ControlConfiguration(Guid Epoch, string TargetNode, ZoneScope[] Zones, string KeyFile, string? ConnectionStringFile, string? PublicationSocket, GrantConfiguration[]? Grants, uint SigningScanSeconds = 60);
