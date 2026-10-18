using System.Runtime.ExceptionServices;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

internal static class HostProcessScope
{
    internal static async Task RunAsync(Func<HostProcess> create, Func<HostProcess, Task> body)
    {
        Exception? original = null;
        try
        {
            var host = create();
            await using var lifetime = host.ConfigureAwait(true);
            original = await Record.ExceptionAsync(() => body(host)).ConfigureAwait(true);
        }
        catch (Exception cleanup) when (original is not null)
        {
            throw new AggregateException(original, cleanup);
        }
        if (original is not null) ExceptionDispatchInfo.Capture(original).Throw();
    }
}
