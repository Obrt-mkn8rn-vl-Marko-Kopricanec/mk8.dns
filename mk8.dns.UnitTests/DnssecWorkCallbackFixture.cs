using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class DnssecWorkCallbackFixture : IAsyncDisposable
{
    private readonly ManualResetEventSlim released = new();
    private readonly TaskCompletionSource<DnsUpstreamEvidence> held = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CancellationTokenRegistration registration;

    internal DnssecWorkCallbackFixture()
    {
        Source.Override = (question, server, token) =>
        {
            if (Source.Calls.Count != 1) return ValueTask.FromResult(Source.Default(question, server));
            Token = token;
            registration = token.Register(() =>
            {
                CallbackEntered.TrySetResult();
                try
                {
                    if (!released.Wait(DnssecWorkFixture.Timeout)) throw new TimeoutException("The controlled DNSSEC callback was not released.");
                }
                finally { CallbackExited.TrySetResult(); }
            });
            Registered.TrySetResult();
            return new ValueTask<DnsUpstreamEvidence>(held.Task);
        };
        Cache = new CachingDnssecResolver(Source.Resolver());
        Resolver = new CoalescingDnssecResolver(Cache, new DnssecWorkPolicy(1, 8, TimeSpan.FromSeconds(1)),
            new ObservedClock(Clock, TimerDisposed));
    }

    internal OnlineDnssecFixture Source { get; } = new();
    internal RecursiveCacheClock Clock { get; } = new();
    internal CachingDnssecResolver Cache { get; }
    internal CoalescingDnssecResolver Resolver { get; }
    internal CancellationToken Token { get; private set; }
    internal TaskCompletionSource Registered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CallbackEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CallbackExited { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource TimerDisposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal void FinishProvider() => held.TrySetResult(Source.Default(new DnsQuestion(Source.Root, 48, 1), OnlineDnssecFixture.RootServer));
    internal void ReleaseCallback() => released.Set();

    public async ValueTask DisposeAsync()
    {
        var drain = Resolver.DisposeAsync().AsTask();
        FinishProvider(); ReleaseCallback();
        try { await drain.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true); }
        finally
        {
            await registration.DisposeAsync().ConfigureAwait(true);
            await Cache.DisposeAsync().ConfigureAwait(true);
            released.Dispose(); Source.Dispose();
        }
    }

    private sealed class ObservedClock(RecursiveCacheClock clock, TaskCompletionSource disposed) : TimeProvider
    {
        public override long TimestampFrequency => clock.TimestampFrequency;
        public override long GetTimestamp() => clock.GetTimestamp();
        public override DateTimeOffset GetUtcNow() => clock.GetUtcNow();
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
            => new ObservedTimer(clock.CreateTimer(callback, state, dueTime, period), disposed);
    }

    private sealed class ObservedTimer(ITimer timer, TaskCompletionSource disposed) : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => timer.Change(dueTime, period);
        public void Dispose() { timer.Dispose(); disposed.TrySetResult(); }
        public async ValueTask DisposeAsync()
        {
            await timer.DisposeAsync().ConfigureAwait(true); disposed.TrySetResult();
        }
    }
}
