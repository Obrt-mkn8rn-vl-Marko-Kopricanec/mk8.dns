using System.Runtime.ExceptionServices;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

internal static class TestTaskSettlement
{
    internal static async Task RunAsync(Func<Task> observe, Func<Task> settle)
    {
        var primary = await Record.ExceptionAsync(observe).ConfigureAwait(true);
        var cleanup = await Record.ExceptionAsync(settle).ConfigureAwait(true);
        if (primary is not null && cleanup is not null) throw new AggregateException(primary, cleanup);
        if (primary is not null) ExceptionDispatchInfo.Capture(primary).Throw();
        if (cleanup is not null) ExceptionDispatchInfo.Capture(cleanup).Throw();
    }
}
