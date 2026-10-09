namespace Mk8.Dns.Engine.Recursive;

public sealed class DnsQnameMinimisationPolicy
{
    public DnsQnameMinimisationPolicy(int maximumSteps = 32)
    {
        if (maximumSteps is < 1 or > 128)
            throw new ArgumentOutOfRangeException(nameof(maximumSteps), "Invalid name minimisation step limit.");
        MaximumSteps = maximumSteps;
    }

    public int MaximumSteps { get; }
}
