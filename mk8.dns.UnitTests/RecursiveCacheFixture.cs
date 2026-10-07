using System.Threading.Channels;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class RecursiveCacheFixture : IAsyncDisposable
{
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    internal RecursiveCacheFixture(int maximumFlights = 4, int maximumWaiters = 8, TimeSpan? resolutionTimeout = null)
    {
        Cache = new CachingRecursiveResolver(Source, maximumFlights: maximumFlights, maximumWaiters: maximumWaiters, resolutionTimeout: resolutionTimeout, time: Clock);
    }
    internal ControlledResolver Source { get; } = new();
    internal RecursiveCacheClock Clock { get; } = new();
    internal CachingRecursiveResolver Cache { get; }

    public async ValueTask DisposeAsync()
    {
        var drain = Cache.DisposeAsync().AsTask();
        Source.ReleaseAll();
        await drain.WaitAsync(Timeout).ConfigureAwait(true);
    }

    internal sealed class ControlledResolver : IDnsResolver
    {
        private readonly Lock gate = new();
        private readonly List<Call> calls = [];
        private readonly Channel<Call> started = Channel.CreateUnbounded<Call>();
        internal int Calls { get { lock (gate) return calls.Count; } }
        public ValueTask<DnsAnswer> ResolveAsync(DnsQuestion question, CancellationToken cancellationToken)
        {
            var call = new Call(question, cancellationToken);
            lock (gate) calls.Add(call);
            started.Writer.TryWrite(call);
            return new ValueTask<DnsAnswer>(call.Completion.Task);
        }
        internal async Task<Call> NextAsync() => await started.Reader.ReadAsync().AsTask().WaitAsync(Timeout).ConfigureAwait(true);
        internal void ReleaseAll()
        {
            lock (gate)
                foreach (var call in calls) call.Completion.TrySetResult(new DnsAnswer(2, false, [], [], []));
        }
    }

    internal sealed class Call(DnsQuestion question, CancellationToken cancellationToken)
    {
        internal DnsQuestion Question { get; } = question;
        internal CancellationToken Token { get; } = cancellationToken;
        internal TaskCompletionSource<DnsAnswer> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    internal sealed class ImmediateResolver(Func<DnsQuestion, DnsAnswer> resolve) : IDnsResolver, IAsyncDisposable
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);
        internal bool Disposed { get; private set; }
        public ValueTask<DnsAnswer> ResolveAsync(DnsQuestion question, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(Disposed, this);
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(resolve(question));
        }
        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
