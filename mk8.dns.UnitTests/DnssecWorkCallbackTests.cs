using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecWorkCallbackTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task WaitersCancelBeforeBlockedProviderCallbackWhileBothCleanupHalvesRemainOwned(bool dispose, bool callbackFirst)
    {
        var fixture = new DnssecWorkCallbackFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        var second = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await fixture.Registered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        Task? drain = null;
        if (dispose) drain = fixture.Resolver.DisposeAsync().AsTask();
        else fixture.Clock.Set(TimeSpan.FromSeconds(1));
        await fixture.CallbackEntered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        Assert.False(fixture.CallbackExited.Task.IsCompleted);
        Assert.Equal(0, fixture.Resolver.Statistics.Waiters);
        Assert.Equal(1, fixture.Resolver.Statistics.Workers);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveRequests);
        Assert.True(fixture.Token.IsCancellationRequested);
        if (!dispose)
            Assert.Equal(DnssecResolutionOutcome.Failure,
                (await fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        drain ??= fixture.Resolver.DisposeAsync().AsTask();
        Assert.Same(drain, fixture.Resolver.DisposeAsync().AsTask());
        await FinishInOrderAsync(fixture, drain, callbackFirst).ConfigureAwait(true);
    }

    private static async Task FinishInOrderAsync(DnssecWorkCallbackFixture fixture, Task drain, bool callbackFirst)
    {
        Assert.False(drain.IsCompleted);
        if (callbackFirst)
        {
            fixture.ReleaseCallback();
            await fixture.CallbackExited.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
            Assert.Equal(1, fixture.Clock.ActiveTimers);
        }
        else
        {
            fixture.FinishProvider();
            await fixture.TimerDisposed.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
            Assert.False(fixture.CallbackExited.Task.IsCompleted);
            Assert.Equal(0, fixture.Clock.ActiveTimers);
        }
        Assert.False(drain.IsCompleted);
        Assert.Equal(1, fixture.Resolver.Statistics.Workers);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        fixture.FinishProvider(); fixture.ReleaseCallback();
        await drain.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Resolver.Statistics.Workers);
        Assert.Equal(0, fixture.Cache.Statistics.ActiveRequests);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
    }
}
