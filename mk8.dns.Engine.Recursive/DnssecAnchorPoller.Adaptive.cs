namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecAnchorPoller
{
    // Explicit opt-in. Bootstrap intervals apply only without acknowledged
    // timing. The caller supplies coherent source/timer clocks and journal room.
    public static DnssecAnchorPoller CreateWithAuthenticatedTiming(DnssecAnchorRefresher refresher,
        DnssecAnchorPollingPolicy bootstrapPolicy, TimeProvider time)
        => new(refresher, bootstrapPolicy, time, authenticatedTiming: true);

    private DnssecAnchorPoller(DnssecAnchorRefresher refresher, DnssecAnchorPollingPolicy bootstrapPolicy,
        TimeProvider time, bool authenticatedTiming)
    {
        ArgumentNullException.ThrowIfNull(refresher);
        ArgumentNullException.ThrowIfNull(bootstrapPolicy);
        ArgumentNullException.ThrowIfNull(time);
        _ = refresher.Current;
        this.refresher = refresher; policy = bootstrapPolicy; this.time = time;
        clock = new DnssecResolutionClock(time);
        adaptive = authenticatedTiming ? new AdaptiveSchedule(refresher, bootstrapPolicy, clock) : null;
        cancellation = new CancellationTokenSource(); token = cancellation.Token;
        completion = RunAsync();
    }

    private sealed class AdaptiveSchedule(DnssecAnchorRefresher source, DnssecAnchorPollingPolicy bootstrap,
        DnssecResolutionClock clock)
    {
        private long since = clock.GetTimestamp();
        private long attemptedRevision;
        internal bool Retry { get; set; }
        internal void BeginAttempt()
        {
            since = clock.GetTimestamp();
            attemptedRevision = source.Current.Revision;
        }
        internal TimeSpan Delay()
        {
            var elapsed = clock.GetElapsedTime(since, clock.GetTimestamp());
            if (elapsed < TimeSpan.Zero) elapsed = TimeSpan.Zero;
            var receipt = source.CurrentTiming;
            // A separately acknowledged refresh satisfies the old retry episode.
            if (Retry && receipt is not null && receipt.Revision != attemptedRevision) Retry = false;
            var candidate = Retry
                ? (receipt?.Proof.RetryInterval ?? bootstrap.RetryInterval) - elapsed
                : receipt?.RemainingQueryInterval ?? bootstrap.RefreshInterval - elapsed;
            // Wall jumps or an overdue receipt cannot bypass local attempt spacing.
            var minimum = TimeSpan.FromHours(1) - elapsed;
            return candidate > minimum ? candidate : minimum;
        }
    }
}
