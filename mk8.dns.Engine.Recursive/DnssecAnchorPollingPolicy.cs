namespace Mk8.Dns.Engine.Recursive;

// Explicit caller policy, not automatically derived RFC5011 timing. The caller
// must select intervals from actual authenticated TTL/expiry and journal capacity.
public sealed class DnssecAnchorPollingPolicy
{
    public DnssecAnchorPollingPolicy(TimeSpan refreshInterval, TimeSpan retryInterval, int maximumAttempts = 16)
    {
        if (refreshInterval < TimeSpan.FromHours(1) || refreshInterval > TimeSpan.FromDays(15))
            throw new ArgumentOutOfRangeException(nameof(refreshInterval));
        if (retryInterval < TimeSpan.FromHours(1) || retryInterval > TimeSpan.FromDays(1) || retryInterval > refreshInterval)
            throw new ArgumentOutOfRangeException(nameof(retryInterval));
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumAttempts, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumAttempts, 256);
        RefreshInterval = refreshInterval; RetryInterval = retryInterval; MaximumAttempts = maximumAttempts;
    }

    public TimeSpan RefreshInterval { get; }
    public TimeSpan RetryInterval { get; }
    public int MaximumAttempts { get; }
}
