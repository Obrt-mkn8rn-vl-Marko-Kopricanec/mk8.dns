using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class DnssecWorkFixture : IAsyncDisposable
{
    private readonly TaskCompletionSource<DnsUpstreamEvidence> held = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal DnssecWorkFixture(int maximumWorkers = 2, int maximumWaiters = 8)
    {
        Source.Override = (question, server, token) =>
        {
            if (question.Type != 48 || Source.Calls.Count != 1) return ValueTask.FromResult(Source.Default(question, server));
            Token = token; Entered.TrySetResult(); return new ValueTask<DnsUpstreamEvidence>(held.Task);
        };
        Cache = new CachingDnssecResolver(Source.Resolver());
        Resolver = new CoalescingDnssecResolver(Cache, new DnssecWorkPolicy(maximumWorkers, maximumWaiters, TimeSpan.FromSeconds(1)), Clock);
    }

    internal OnlineDnssecFixture Source { get; } = new();
    internal RecursiveCacheClock Clock { get; } = new();
    internal CachingDnssecResolver Cache { get; }
    internal CoalescingDnssecResolver Resolver { get; }
    internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal CancellationToken Token { get; private set; }
    internal static TimeSpan Timeout { get; } = TimeSpan.FromSeconds(5);
    internal static DnsQuestion Question { get; } = DnssecCacheResolutionTests.Question();

    internal void Release() => held.TrySetResult(Source.Default(new DnsQuestion(Source.Root, 48, 1), OnlineDnssecFixture.RootServer));
    internal void Fail() => held.TrySetException(new InvalidOperationException("Controlled authenticated source fault."));

    public async ValueTask DisposeAsync()
    {
        var drain = Resolver.DisposeAsync().AsTask();
        Release();
        try { await drain.WaitAsync(Timeout).ConfigureAwait(true); }
        finally { await Cache.DisposeAsync().ConfigureAwait(true); Source.Dispose(); }
    }
}
