using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecWorkLifecycleTests
{
    [Fact]
    public async Task DeadlineIsSharedByLateJoinerAndKeepsIgnoringProviderOwned()
    {
        var fixture = new DnssecWorkFixture(maximumWorkers: 1);
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        fixture.Clock.Set(TimeSpan.FromMilliseconds(900));
        var second = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        fixture.Clock.Set(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        Assert.Equal(1, fixture.Resolver.Statistics.Workers);
        Assert.Equal(0, fixture.Resolver.Statistics.Waiters);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveRequests);
        Assert.Equal(1, fixture.Clock.ActiveTimers);
        var drain = fixture.Resolver.DisposeAsync().AsTask(); Assert.False(drain.IsCompleted);
        fixture.Release(); await drain.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
    }

    [Fact]
    public async Task ClearBreaksJoiningAndFencesLateStoreWithoutCancelingAdmittedSnapshot()
    {
        var fixture = new DnssecWorkFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        fixture.Resolver.Clear();
        Assert.False(fixture.Token.IsCancellationRequested);
        var newer = await fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, newer.Outcome);
        Assert.Equal(2, fixture.Resolver.Statistics.Started);
        Assert.Equal(0, fixture.Resolver.Statistics.Coalesced);
        fixture.Release(); await first.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(1, fixture.Cache.Statistics.Entries);
        Assert.Equal(0, fixture.Resolver.Statistics.Workers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClosingCancelsWaitersDrainsActualSourceAndDoesNotDisposeCallerSource(bool fault)
    {
        var fixture = new DnssecWorkFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        var drain = fixture.Resolver.DisposeAsync().AsTask();
        Assert.Same(drain, fixture.Resolver.DisposeAsync().AsTask());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        Assert.False(drain.IsCompleted);
        Assert.Throws<ObjectDisposedException>(fixture.Resolver.Clear);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        if (fault) fixture.Fail(); else fixture.Release();
        await drain.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Resolver.Statistics.Workers);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        Assert.Equal(DnssecResolutionOutcome.Authenticated,
            (await fixture.Cache.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
    }
}
