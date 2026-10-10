namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecAnchorPoller
{
    private async Task PollAdaptiveAsync(AdaptiveSchedule schedule)
    {
        for (var index = 0; index < policy.MaximumAttempts; index++)
        {
            if (!await WaitAdaptiveAsync(schedule).ConfigureAwait(false) || token.IsCancellationRequested) return;
            schedule.BeginAttempt();
            lock (gate) attempts++;
            DnssecAnchorRefreshOutcome outcome;
            try { outcome = await refresher.RefreshAsync(token).ConfigureAwait(false); }
            catch (OperationCanceledException error) when (token.IsCancellationRequested && error.CancellationToken == token)
            {
                try { _ = refresher.Current; }
                catch (Exception stateError) { throw new AggregateException(error, stateError); }
                return;
            }
            lock (gate)
            {
                switch (outcome)
                {
                    case DnssecAnchorRefreshOutcome.Applied: applied++; break;
                    case DnssecAnchorRefreshOutcome.Refused: refused++; break;
                    case DnssecAnchorRefreshOutcome.Busy: busy++; break;
                    default: throw new InvalidOperationException("Unknown anchor refresh outcome.");
                }
            }
            if (token.IsCancellationRequested) return;
            schedule.Retry = outcome != DnssecAnchorRefreshOutcome.Applied;
        }
    }

    private async Task<bool> WaitAdaptiveAsync(AdaptiveSchedule schedule)
    {
        for (var changes = 0; changes < 128; changes++)
        {
            if (token.IsCancellationRequested) return false;
            var delay = schedule.Delay();
            if (delay <= TimeSpan.Zero) return true;
            if (!await WaitAsync(delay).ConfigureAwait(false)) return false;
            // Reread the current acknowledged receipt, never the old projection.
        }
        throw new IOException("Anchor timing changed too many times before an attempt.");
    }
}
