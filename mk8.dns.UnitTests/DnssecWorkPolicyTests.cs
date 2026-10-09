using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecWorkPolicyTests
{
    [Theory]
    [InlineData(0, 1, 1000)]
    [InlineData(257, 1, 1000)]
    [InlineData(1, 0, 1000)]
    [InlineData(1, 65537, 1000)]
    [InlineData(1, 1, 49)]
    [InlineData(1, 1, 120001)]
    public void InvalidLimitsFailBeforeWorkCreation(int workers, int waiters, int milliseconds)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new DnssecWorkPolicy(workers, waiters, TimeSpan.FromMilliseconds(milliseconds)));

    [Theory]
    [InlineData(1, 1, 50)]
    [InlineData(256, 65536, 120000)]
    public void BoundsAreImmutable(int workers, int waiters, int milliseconds)
    {
        var policy = new DnssecWorkPolicy(workers, waiters, TimeSpan.FromMilliseconds(milliseconds));
        Assert.Equal(workers, policy.MaximumWorkers); Assert.Equal(waiters, policy.MaximumWaiters);
        Assert.Equal(TimeSpan.FromMilliseconds(milliseconds), policy.ResolutionTimeout);
    }

    [Fact]
    public async Task NullSourceOrPolicyFailsBeforeTimerCreation()
    {
        using var fixture = new OnlineDnssecFixture();
        var source = new CachingDnssecResolver(fixture.Resolver());
        await using var lifetime = source.ConfigureAwait(true);
        Assert.Throws<ArgumentNullException>(() => new CoalescingDnssecResolver(null!, new DnssecWorkPolicy()));
        Assert.Throws<ArgumentNullException>(() => new CoalescingDnssecResolver(source, null!));
    }
}
