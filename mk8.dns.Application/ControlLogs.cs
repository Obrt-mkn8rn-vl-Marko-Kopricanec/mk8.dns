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

internal static partial class ControlLogs
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Information, Message = "Publication retry pending ({FailureType}).")]
    internal static partial void Pending(ILogger logger, string failureType);

    [LoggerMessage(EventId = 2, Level = LogLevel.Information, Message = "DNSSEC renewal committed for zone {ZoneId}.")]
    internal static partial void Renewed(ILogger logger, Guid zoneId);

    [LoggerMessage(EventId = 3, Level = LogLevel.Information, Message = "DNSSEC renewal requires retry or reconciliation for zone {ZoneId}.")]
    internal static partial void RenewalPending(ILogger logger, Guid zoneId);
}
