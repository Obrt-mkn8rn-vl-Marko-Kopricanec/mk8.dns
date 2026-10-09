namespace Mk8.Dns.UnitTests;

internal sealed class DnssecWorkTimerClock : TimeProvider
{
    private readonly RecursiveCacheClock clock = new();
    internal TaskCompletionSource DisposalEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DisposalReleased { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public override long TimestampFrequency => clock.TimestampFrequency;
    public override long GetTimestamp() => clock.GetTimestamp();
    public override DateTimeOffset GetUtcNow() => clock.GetUtcNow();
    internal void Set(double seconds) => clock.Set(TimeSpan.FromSeconds(seconds));
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        => new HeldTimer(clock.CreateTimer(callback, state, dueTime, period), DisposalEntered, DisposalReleased);

    private sealed class HeldTimer(ITimer timer, TaskCompletionSource entered, TaskCompletionSource released) : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => timer.Change(dueTime, period);
        public void Dispose() => timer.Dispose();
        public async ValueTask DisposeAsync()
        {
            entered.TrySetResult();
            await released.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
            await timer.DisposeAsync().ConfigureAwait(true);
        }
    }
}
