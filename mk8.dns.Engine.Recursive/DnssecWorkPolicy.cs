namespace Mk8.Dns.Engine.Recursive;

public sealed class DnssecWorkPolicy
{
    public DnssecWorkPolicy(int maximumWorkers = 64, int maximumWaiters = 1024, TimeSpan? resolutionTimeout = null)
    {
        var timeout = resolutionTimeout ?? TimeSpan.FromSeconds(10);
        if (maximumWorkers is < 1 or > 256 || maximumWaiters is < 1 or > 65536
            || timeout < TimeSpan.FromMilliseconds(50) || timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(maximumWorkers), "Invalid authenticated resolution work limits.");
        MaximumWorkers = maximumWorkers;
        MaximumWaiters = maximumWaiters;
        ResolutionTimeout = timeout;
    }

    public int MaximumWorkers { get; }
    public int MaximumWaiters { get; }
    public TimeSpan ResolutionTimeout { get; }
}
