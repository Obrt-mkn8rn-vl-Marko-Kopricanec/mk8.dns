using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class RecursiveCacheCallbackFixture : IAsyncDisposable
{
    internal RecursiveCacheCallbackFixture()
    {
        Cache = new CachingRecursiveResolver(Source, maximumFlights: 1,
            resolutionTimeout: TimeSpan.FromSeconds(1), time: new ObservedClock(Clock, TimerDisposed));
    }

    internal BlockingResolver Source { get; } = new();
    internal RecursiveCacheClock Clock { get; } = new();
    internal TaskCompletionSource TimerDisposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal CachingRecursiveResolver Cache { get; }

    public async ValueTask DisposeAsync()
    {
        var drain = Cache.DisposeAsync().AsTask();
        Source.FinishProvider();
        Source.ReleaseCallback();
        try { await drain.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true); }
        finally { await Source.DisposeAsync().ConfigureAwait(true); }
    }

    internal sealed class BlockingResolver : IDnsResolver, IAsyncDisposable
    {
        private readonly ManualResetEventSlim released = new();
        private readonly TaskCompletionSource<DnsAnswer> answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private CancellationTokenRegistration registration;
        private int calls;

        internal int Calls => Volatile.Read(ref calls);
        internal CancellationToken Token { get; private set; }
        internal TaskCompletionSource Registered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource CallbackEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource CallbackExited { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask<DnsAnswer> ResolveAsync(DnsQuestion question, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref calls);
            Token = cancellationToken;
            // This later registration deliberately holds the CTS serial callback dispatcher.
            registration = cancellationToken.Register(() =>
            {
                CallbackEntered.TrySetResult();
                try
                {
                    if (!released.Wait(RecursiveCacheFixture.Timeout))
                        throw new TimeoutException("The controlled provider callback was not released.");
                }
                finally { CallbackExited.TrySetResult(); }
            });
            Registered.TrySetResult();
            return new ValueTask<DnsAnswer>(answer.Task);
        }

        internal void FinishProvider() => answer.TrySetResult(RecursiveCacheTests.Positive(RecursiveCacheTests.Query("www.example."), 30));
        internal void ReleaseCallback() => released.Set();

        public async ValueTask DisposeAsync()
        {
            ReleaseCallback();
            await registration.DisposeAsync().ConfigureAwait(true);
            released.Dispose();
        }
    }

    private sealed class ObservedClock(RecursiveCacheClock clock, TaskCompletionSource timerDisposed) : TimeProvider
    {
        public override long TimestampFrequency => clock.TimestampFrequency;
        public override long GetTimestamp() => clock.GetTimestamp();
        public override DateTimeOffset GetUtcNow() => clock.GetUtcNow();
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
            => new ObservedTimer(clock.CreateTimer(callback, state, dueTime, period), timerDisposed);
    }

    private sealed class ObservedTimer(ITimer timer, TaskCompletionSource disposed) : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => timer.Change(dueTime, period);
        public void Dispose()
        {
            timer.Dispose();
            disposed.TrySetResult();
        }
        public async ValueTask DisposeAsync()
        {
            await timer.DisposeAsync().ConfigureAwait(true);
            disposed.TrySetResult();
        }
    }
}
