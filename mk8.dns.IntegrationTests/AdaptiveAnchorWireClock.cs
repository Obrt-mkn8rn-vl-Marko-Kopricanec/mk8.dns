using System.Threading.Channels;

namespace Mk8.Dns.IntegrationTests;

// One deterministic one-shot timer; no wall-clock sleeps or target listeners.
internal sealed class AdaptiveAnchorWireClock : TimeProvider
{
    private readonly Lock gate = new();
    private Timer? current;
    private long ticks;
    private readonly Channel<TimeSpan> created = Channel.CreateUnbounded<TimeSpan>();
    internal async Task<TimeSpan> NextTimerAsync()
        => await created.Reader.ReadAsync().AsTask().WaitAsync(AnchorRefreshWireFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
    internal int ActiveTimers { get { lock (gate) return current is null ? 0 : 1; } }
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => Interlocked.Read(ref ticks);
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(100).AddTicks(GetTimestamp());
    internal void Set(TimeSpan elapsed)
    {
        Interlocked.Exchange(ref ticks, elapsed.Ticks);
        Timer? timer; lock (gate) timer = current;
        timer?.Fire(elapsed.Ticks);
    }
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new Timer(this, callback, state, dueTime, period);
        lock (gate)
        {
            if (current is not null) throw new InvalidOperationException("Only one owned timer is permitted.");
            current = timer;
        }
        if (!created.Writer.TryWrite(dueTime)) throw new InvalidOperationException("Timer observation refused."); return timer;
    }
    private sealed class Timer : ITimer
    {
        private readonly Lock gate = new();
        private readonly AdaptiveAnchorWireClock owner;
        private readonly TimerCallback callback;
        private readonly object? state;
        private readonly TaskCompletionSource stopped = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private long due;
        private bool disposed;
        private int running;
        internal Timer(AdaptiveAnchorWireClock owner, TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            this.owner = owner; this.callback = callback; this.state = state; Change(dueTime, period);
        }
        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(period, Timeout.InfiniteTimeSpan);
            lock (gate)
            {
                if (disposed) return false;
                due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : owner.GetTimestamp() + dueTime.Ticks;
                return true;
            }
        }
        internal void Fire(long now)
        {
            lock (gate) { if (disposed || now < due) return; due = long.MaxValue; running++; }
            try { callback(state); }
            finally { lock (gate) { running--; if (disposed && running == 0) stopped.TrySetResult(); } }
        }
        public void Dispose() => Retire();
        private void Retire()
        {
            lock (gate) { disposed = true; if (running == 0) stopped.TrySetResult(); }
            lock (owner.gate) if (ReferenceEquals(owner.current, this)) owner.current = null;
        }
        public ValueTask DisposeAsync() { Retire(); return new(stopped.Task); }
    }
}
