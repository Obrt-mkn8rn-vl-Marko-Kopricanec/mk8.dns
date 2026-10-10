namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecAnchorPoller
{
    private async Task PollAsync()
    {
        // Startup also waits: no implicit immediate acquisition or burst catch-up.
        var interval = policy.RefreshInterval;
        for (var index = 0; index < policy.MaximumAttempts; index++)
        {
            if (!await WaitAsync(interval).ConfigureAwait(false) || token.IsCancellationRequested) return;
            lock (gate) attempts++;
            DnssecAnchorRefreshOutcome outcome;
            try { outcome = await refresher.RefreshAsync(token).ConfigureAwait(false); }
            catch (OperationCanceledException error) when (token.IsCancellationRequested && error.CancellationToken == token)
            {
                // Healthy acquisition cancellation may stop normally. A canceled
                // ambiguous commit faults the source and must not become success.
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
            interval = outcome == DnssecAnchorRefreshOutcome.Applied ? policy.RefreshInterval : policy.RetryInterval;
        }
    }

    private async Task<bool> WaitAsync(TimeSpan interval)
    {
        var began = clock.GetTimestamp();
        for (var signals = 0; signals < 128; signals++)
        {
            if (token.IsCancellationRequested) return false;
            var elapsed = clock.GetElapsedTime(began, clock.GetTimestamp());
            var remaining = interval - (elapsed < TimeSpan.Zero ? TimeSpan.Zero : elapsed);
            if (remaining <= TimeSpan.Zero) return true;
            var delay = new PollDelay(time, remaining);
            lock (gate) { pending = delay.Ready; if (token.IsCancellationRequested) delay.Stop(); }
            try { if (!await delay.Ready.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false)) return false; }
            finally
            {
                try { await delay.DisposeAsync().ConfigureAwait(false); }
                finally { lock (gate) if (ReferenceEquals(pending, delay.Ready)) pending = null; }
            }
        }
        throw new IOException("Anchor polling clock produced too many early timer signals.");
    }
}
