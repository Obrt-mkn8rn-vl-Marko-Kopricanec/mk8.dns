namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecAnchorPoller
{
    private sealed class PollDelay : IAsyncDisposable
    {
        private readonly ITimer timer;
        internal PollDelay(TimeProvider time, TimeSpan delay)
            => timer = time.CreateTimer(static state => ((PollDelay)state!).Ready.TrySetResult(true), this, delay, Timeout.InfiniteTimeSpan);
        internal TaskCompletionSource<bool> Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal void Stop() => Ready.TrySetResult(false);
        public ValueTask DisposeAsync() => timer.DisposeAsync();
    }
}
