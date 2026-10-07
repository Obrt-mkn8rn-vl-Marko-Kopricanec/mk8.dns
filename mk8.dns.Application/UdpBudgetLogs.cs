namespace Mk8.Dns.Application;

internal static partial class UdpBudgetLogs
{
    [LoggerMessage(140, LogLevel.Information, "UDP response budget totals: admitted {Admitted}, dropped {Dropped}, tracked prefixes {TrackedPrefixes}.")]
    internal static partial void Totals(ILogger logger, long admitted, long dropped, int trackedPrefixes);
}
