using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class RecursiveCacheCallbackFixture : IAsyncDisposable
{
    internal RecursiveCacheCallbackFixture(bool holdTimer = false, bool failTimer = false)
    {
        if (!holdTimer) TimerRelease.SetResult();
        TimerFailure = failTimer ? new IOException("Owned timer disposal failure.") : null;
        Cache = new CachingRecursiveResolver(Source, maximumFlights: 1,
            resolutionTimeout: TimeSpan.FromSeconds(1), time: new ObservedClock(this));
    }

    internal BlockingResolver Source { get; } = new();
    internal RecursiveCacheClock Clock { get; } = new();
    internal TaskCompletionSource TimerDisposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource TimerDisposing { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource TimerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal IOException? TimerFailure { get; }
    internal CachingRecursiveResolver Cache { get; }

    public async ValueTask DisposeAsync()
    {
        var drain = Cache.DisposeAsync().AsTask();
        TimerRelease.TrySetResult();
        Source.FinishProvider();
        Source.ReleaseCallback();
        try { await drain.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
        catch (InvalidOperationException) when (TimerFailure is not null && drain.IsFaulted) { }
        finally { await Source.DisposeAsync().ConfigureAwait(true); }
    }

    internal sealed class BlockingResolver : IDnsResolver, IAsyncDisposable
    {
        private readonly ManualResetEventSlim released = new();
        private readonly TaskCompletionSource<DnsAnswer> answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private CancellationTokenRegistration registration;
        private int calls;

        internal Exception? CallbackFailure { get; set; }
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
                    if (!released.Wait(RecursiveCacheFixture.Timeout, CancellationToken.None))
                        throw new TimeoutException("The controlled provider callback was not released.");
                    if (CallbackFailure is not null) throw CallbackFailure;
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

    private sealed class ObservedClock(RecursiveCacheCallbackFixture fixture) : TimeProvider
    {
        public override long TimestampFrequency => fixture.Clock.TimestampFrequency;
        public override long GetTimestamp() => fixture.Clock.GetTimestamp();
        public override DateTimeOffset GetUtcNow() => fixture.Clock.GetUtcNow();
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
            => new ObservedTimer(fixture.Clock.CreateTimer(callback, state, dueTime, period), fixture);
    }

    private sealed class ObservedTimer(ITimer timer, RecursiveCacheCallbackFixture fixture) : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => timer.Change(dueTime, period);
        public void Dispose()
        {
            timer.Dispose();
            fixture.TimerDisposed.TrySetResult();
        }
        public async ValueTask DisposeAsync()
        {
            fixture.TimerDisposing.TrySetResult();
            await fixture.TimerRelease.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
            await timer.DisposeAsync().ConfigureAwait(true);
            fixture.TimerDisposed.TrySetResult();
            if (fixture.TimerFailure is not null) throw fixture.TimerFailure;
        }
    }
}
