using System.Threading.Channels;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class AnchorPollingFixture : IAsyncDisposable
{
    private readonly List<DnssecAnchorPoller> pollers = [];
    private readonly HashSet<DnssecAnchorPoller> expectedFaults = [];
    internal AnchorPollingFixture()
    {
        Clock = new ClockProvider(Source.Keys.Clock);
        Refresher = Source.Create();
    }

    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    internal AnchorRefreshFixture Source { get; } = new();
    internal DnssecAnchorRefresher Refresher { get; }
    internal ClockProvider Clock { get; }
    internal DnssecAnchorPoller Create(int maximumAttempts = 3, double refreshHours = 2, double retryHours = 1)
    {
        var poller = new DnssecAnchorPoller(Refresher, new DnssecAnchorPollingPolicy(TimeSpan.FromHours(refreshHours),
            TimeSpan.FromHours(retryHours), maximumAttempts), Clock);
        pollers.Add(poller); return poller;
    }
    internal void ExpectFault(DnssecAnchorPoller poller) => expectedFaults.Add(poller);
    public async ValueTask DisposeAsync()
    {
        Clock.DisposalReleased.TrySetResult();
        try
        {
            foreach (var poller in pollers)
            {
                try { await poller.DisposeAsync().AsTask().WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
                catch (IOException) when (expectedFaults.Contains(poller)) { /* Separately asserted controlled fault. */ }
                catch (AggregateException) when (expectedFaults.Contains(poller)) { /* Separately asserted controlled fault. */ }
                catch (OperationCanceledException) when (expectedFaults.Contains(poller)) { /* Separately asserted controlled fault. */ }
                catch (InvalidOperationException) when (expectedFaults.Contains(poller)) { /* Separately asserted controlled fault. */ }
            }
        }
        finally { await Refresher.DisposeAsync().ConfigureAwait(true); Source.Dispose(); }
    }

    internal sealed class ClockProvider(DnssecChainFixture.ClockProvider source) : TimeProvider
    {
        private readonly RecursiveCacheClock timers = new();
        private readonly Channel<TimeSpan> created = Channel.CreateUnbounded<TimeSpan>();
        internal TaskCompletionSource DisposalEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource DisposalReleased { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool HoldDisposal { get; set; }
        internal bool FailCreation { get; set; }
        internal bool FailDisposal { get; set; }
        internal bool FireEarly { get; set; }
        internal int ActiveTimers => timers.ActiveTimers;
        public override long TimestampFrequency => source.TimestampFrequency;
        public override long GetTimestamp() => source.GetTimestamp();
        public override DateTimeOffset GetUtcNow() => source.GetUtcNow();
        internal void Set(double seconds, bool wallOnly = false)
        {
            source.SetWall(100 + (long)seconds);
            if (!wallOnly) { source.SetMonotonic(seconds); timers.Set(TimeSpan.FromSeconds(seconds)); }
        }
        internal async Task<TimeSpan> NextTimerAsync()
            => await created.Reader.ReadAsync().AsTask().WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            if (FailCreation) throw new IOException("Controlled timer creation failure.");
            var timer = new Timer(this, timers.CreateTimer(callback, state, dueTime, period), HoldDisposal, FailDisposal);
            if (FireEarly) callback(state);
            if (!created.Writer.TryWrite(dueTime)) throw new InvalidOperationException("Timer observation refused.");
            return timer;
        }

        private sealed class Timer(ClockProvider owner, ITimer timer, bool hold, bool fail) : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => timer.Change(dueTime, period);
            public void Dispose() => timer.Dispose();
            public async ValueTask DisposeAsync()
            {
                if (hold)
                {
                    owner.DisposalEntered.TrySetResult();
                    await owner.DisposalReleased.Task.WaitAsync(Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
                }
                await timer.DisposeAsync().ConfigureAwait(true);
                if (fail) throw new IOException("Controlled timer disposal failure.");
            }
        }
    }
}
