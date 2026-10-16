using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class RecursiveCacheCallbackFixture : IAsyncDisposable
{
    internal RecursiveCacheCallbackFixture(bool holdTimer = false, bool failTimer = false)
    {
        if (!holdTimer) TimerRelease.SetResult();
        TimerFailure = failTimer ? new IOException("Owned timer disposal failure.") : null;
        TimerProvider = new ObservedClock(this);
        Cache = new CachingRecursiveResolver(Source, maximumFlights: 1,
            resolutionTimeout: TimeSpan.FromSeconds(1), time: TimerProvider);
    }

    internal TimeProvider TimerProvider { get; }
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
        Source.FinishProvider(); Source.ReleaseCallback();
        await TestTaskSettlement.InOrderAsync(
            () => TestTaskSettlement.WaitAsync(drain.WaitAsync(CancellationToken.None), RecursiveCacheFixture.Timeout,
                error => TimerFailure is not null && error is InvalidOperationException wrapper
                    && wrapper.InnerException is { } inner && ExpectedCleanup(inner)),
            async () => await Source.DisposeAsync().ConfigureAwait(true)).ConfigureAwait(true);
    }

    private bool ExpectedCleanup(Exception error)
        => error is AggregateException aggregate ? aggregate.Flatten().InnerExceptions.All(ExpectedCleanup)
            : ReferenceEquals(error, TimerFailure) || ReferenceEquals(error, Source.CallbackFailure);

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
            await TestTaskSettlement.RunAsync(
                () => fixture.TimerRelease.Task.WaitAsync(RecursiveCacheFixture.Timeout, TimeProvider.System, CancellationToken.None),
                async () =>
                {
                    await timer.DisposeAsync().ConfigureAwait(true);
                    fixture.TimerDisposed.TrySetResult();
                    if (fixture.TimerFailure is not null) throw fixture.TimerFailure;
                }).ConfigureAwait(true);
        }
    }
}
