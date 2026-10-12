using System.Text.Json;
using Mk8.Dns.Application.DAL;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.Application;

internal sealed partial record RecursiveStartupConfiguration
{
    private static DnssecAnchorPollingPolicy Refresh(JsonElement value)
    {
        RequireFields(value, ["refreshIntervalSeconds", "retryIntervalSeconds", "maximumAttempts"]);
        return new DnssecAnchorPollingPolicy(
            TimeSpan.FromSeconds(Number(value, "refreshIntervalSeconds", 3600, 1296000)),
            TimeSpan.FromSeconds(Number(value, "retryIntervalSeconds", 3600, 86400)),
            (int)Number(value, "maximumAttempts", 1, 256));
    }

    internal void RequireRefreshCapacity(FileAnchorCheckpointStore store)
    {
        if (RefreshPolicy is not { } policy) return;
        var revision = store.Revision;
        var live = Retention ? revision - store.FirstRetainedRevision + 1 : revision;
        if (revision > long.MaxValue - policy.MaximumAttempts
            || live > FileAnchorCheckpointStore.MaximumGenerations - policy.MaximumAttempts)
        {
            throw new InvalidDataException("The existing journal must have room for every configured refresh attempt.");
        }
    }
}
