using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecWorkSharingTests
{
    [Fact]
    public async Task CanonicalExactQuestionSharesOneOwnedAuthenticatedResolution()
    {
        var fixture = new DnssecWorkFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        var second = fixture.Resolver.ResolveDnssecAsync(DnssecCacheResolutionTests.Question("WWW.Example."), CancellationToken.None).AsTask();
        Assert.Equal(1, fixture.Resolver.Statistics.Workers);
        Assert.Equal(2, fixture.Resolver.Statistics.Waiters);
        Assert.Equal(1, fixture.Resolver.Statistics.Coalesced);
        fixture.Release();
        var results = await Task.WhenAll(first, second).WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        Assert.All(results, result => Assert.Equal(DnssecResolutionOutcome.Authenticated, result.Outcome));
        Assert.Equal(Assert.Single(results[0].Answers).GetData(), Assert.Single(results[1].Answers).GetData());
        Assert.Equal(2, fixture.Source.Calls.Count);
        Assert.Equal(1, fixture.Cache.Statistics.Entries);
        Assert.Equal(0, fixture.Resolver.Statistics.Workers);
        Assert.Equal(0, fixture.Resolver.Statistics.Waiters);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
    }

    [Fact]
    public async Task TypeAndClassAreSeparateFlightIdentities()
    {
        var fixture = new DnssecWorkFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        var other = await fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question with { Type = 28 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Authenticated, other.Outcome);
        Assert.Equal(2, fixture.Resolver.Statistics.Started);
        Assert.Equal(0, fixture.Resolver.Statistics.Coalesced);
        var unsupported = await fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question with { Class = 3 }, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, unsupported.Outcome);
        Assert.Equal(3, fixture.Resolver.Statistics.Started);
        fixture.Release();
        await first.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
    }

    [Fact]
    public async Task WaiterQuotaRejectsAnotherJoinWithoutCancelingExistingWork()
    {
        var fixture = new DnssecWorkFixture(maximumWaiters: 1);
        await using var lifetime = fixture.ConfigureAwait(true);
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        var rejected = await fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(DnssecResolutionOutcome.Failure, rejected.Outcome);
        Assert.Empty(rejected.Answers); Assert.Empty(rejected.Authority);
        Assert.Equal(1, fixture.Resolver.Statistics.AdmissionRejections);
        Assert.Equal(1, fixture.Resolver.Statistics.Waiters);
        Assert.False(fixture.Token.IsCancellationRequested);
        fixture.Release(); await first.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
    }

    [Fact]
    public async Task OneCanceledWaiterDoesNotCancelAnotherSharedWaiter()
    {
        var fixture = new DnssecWorkFixture();
        await using var lifetime = fixture.ConfigureAwait(true);
        using var cancellation = new CancellationTokenSource();
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, cancellation.Token).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        var second = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).AsTask();
        await cancellation.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        Assert.Equal(1, fixture.Resolver.Statistics.Waiters);
        Assert.False(fixture.Token.IsCancellationRequested);
        fixture.Release();
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await second.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true)).Outcome);
    }

    [Fact]
    public async Task LastWaiterCancellationRetainsWorkerAndCannotStoreLateResult()
    {
        var fixture = new DnssecWorkFixture(maximumWorkers: 1);
        await using var lifetime = fixture.ConfigureAwait(true);
        using var cancellation = new CancellationTokenSource();
        var first = fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, cancellation.Token).AsTask();
        await fixture.Entered.Task.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        await cancellation.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(DnssecWorkFixture.Timeout)).ConfigureAwait(true);
        Assert.True(fixture.Token.IsCancellationRequested);
        Assert.Equal(1, fixture.Resolver.Statistics.Workers);
        Assert.Equal(0, fixture.Resolver.Statistics.Waiters);
        Assert.Equal(DnssecResolutionOutcome.Failure,
            (await fixture.Resolver.ResolveDnssecAsync(DnssecWorkFixture.Question, CancellationToken.None).ConfigureAwait(true)).Outcome);
        var drain = fixture.Resolver.DisposeAsync().AsTask();
        Assert.False(drain.IsCompleted);
        fixture.Release(); await drain.WaitAsync(DnssecWorkFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        Assert.Equal(0, fixture.Resolver.Statistics.Workers);
    }
}
