namespace Mk8.Dns.UnitTests;

internal sealed class RecursiveCacheClock : TimeProvider
{
    private readonly Lock gate = new();
    private readonly HashSet<Timer> timers = [];
    private long ticks;
    internal DateTimeOffset WallTime { get; set; } = DateTimeOffset.UnixEpoch;
    internal int ActiveTimers { get { lock (gate) return timers.Count; } }
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => Interlocked.Read(ref ticks);
    public override DateTimeOffset GetUtcNow() => WallTime;

    internal void Set(TimeSpan elapsed)
    {
        Interlocked.Exchange(ref ticks, elapsed.Ticks);
        Timer[] current;
        lock (gate) current = timers.ToArray();
        foreach (var timer in current) timer.Fire(elapsed.Ticks);
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new Timer(this, callback, state, dueTime, period);
        lock (gate) timers.Add(timer);
        return timer;
    }

    private sealed class Timer : ITimer
    {
        private readonly Lock gate = new();
        private readonly RecursiveCacheClock clock;
        private readonly TimerCallback callback;
        private readonly object? state;
        private readonly TaskCompletionSource stopped = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private long due;
        private long period;
        private bool disposed;
        private int running;

        internal Timer(RecursiveCacheClock clock, TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            this.clock = clock;
            this.callback = callback;
            this.state = state;
            Change(dueTime, period);
        }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (gate)
            {
                if (disposed) return false;
                due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : clock.GetTimestamp() + dueTime.Ticks;
                this.period = period == Timeout.InfiniteTimeSpan ? long.MaxValue : period.Ticks;
                return true;
            }
        }

        internal void Fire(long now)
        {
            lock (gate)
            {
                if (disposed || now < due) return;
                due = period == long.MaxValue ? long.MaxValue : now + period;
                running++;
            }
            try { callback(state); }
            finally
            {
                lock (gate)
                {
                    running--;
                    if (disposed && running == 0) stopped.TrySetResult();
                }
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                disposed = true;
                if (running == 0) stopped.TrySetResult();
            }
            lock (clock.gate) clock.timers.Remove(this);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return new ValueTask(stopped.Task);
        }
    }
}
