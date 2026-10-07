using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class RecursiveCacheLifetimeTests
{
    private static readonly DnsQuestion Question = RecursiveCacheTests.Query("www.example.");

    [Fact]
    public async Task SharedQuestionsUseOneProviderCallAndIndependentCallerCancellation()
    {
        var fixture = new RecursiveCacheFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        using var canceled = new CancellationTokenSource();
        var first = fixture.Cache.ResolveAsync(Question, canceled.Token).AsTask();
        var second = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var call = await fixture.Source.NextAsync().ConfigureAwait(true);
        Assert.Equal(1, fixture.Source.Calls);
        Assert.Equal(2, fixture.Cache.Statistics.Waiters);
        await canceled.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(RecursiveCacheFixture.Timeout)).ConfigureAwait(true);
        Assert.False(call.Token.IsCancellationRequested);
        Assert.Equal(1, fixture.Cache.Statistics.Waiters);
        call.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30));
        Assert.Equal(0, (await second.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true)).ResponseCode);
        _ = await fixture.Cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(1, fixture.Source.Calls);
        Assert.Equal(1, fixture.Cache.Statistics.Coalesced);
        Assert.Equal(0, fixture.Cache.Statistics.ActiveFlights);
    }

    [Fact]
    public async Task AllDepartedWaitersCancelWorkButDoNotReleaseItsSlot()
    {
        var fixture = new RecursiveCacheFixture(maximumFlights: 1);
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        using var canceled = new CancellationTokenSource();
        var first = fixture.Cache.ResolveAsync(Question, canceled.Token).AsTask();
        var call = await fixture.Source.NextAsync().ConfigureAwait(true);
        await canceled.CancelAsync().ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(RecursiveCacheFixture.Timeout)).ConfigureAwait(true);
        Assert.True(call.Token.IsCancellationRequested);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(0, fixture.Cache.Statistics.Waiters);
        var rejected = await fixture.Cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(2, rejected.ResponseCode);
        Assert.Equal(1, fixture.Source.Calls);
        var drain = fixture.Cache.DisposeAsync().AsTask();
        Assert.False(drain.IsCompleted);
        call.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30));
        await drain.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
    }

    [Fact]
    public async Task WorkerAndWaiterQuotasRejectWithoutNewProviderCalls()
    {
        var fixture = new RecursiveCacheFixture(maximumFlights: 1, maximumWaiters: 2);
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var first = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var second = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var call = await fixture.Source.NextAsync().ConfigureAwait(true);
        Assert.Equal(2, (await fixture.Cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true)).ResponseCode);
        Assert.Equal(2, (await fixture.Cache.ResolveAsync(RecursiveCacheTests.Query("other.example."), CancellationToken.None).ConfigureAwait(true)).ResponseCode);
        Assert.Equal(1, fixture.Source.Calls);
        Assert.Equal(2, fixture.Cache.Statistics.AdmissionRejections);
        call.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30));
        await Task.WhenAll(first, second).WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
    }

    [Fact]
    public async Task ClearFencesOldResultsAndDoesNotJoinOldGenerationWork()
    {
        var fixture = new RecursiveCacheFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var first = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var old = await fixture.Source.NextAsync().ConfigureAwait(true);
        fixture.Cache.Clear();
        var second = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var fresh = await fixture.Source.NextAsync().ConfigureAwait(true);
        Assert.Equal(2, fixture.Cache.Statistics.ActiveFlights);
        fresh.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30, 43));
        _ = await second.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        old.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30, 42));
        Assert.Equal((byte)42, Assert.Single((await first.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true)).Answers).GetData()[3]);
        var cached = await fixture.Cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true);
        Assert.Equal((byte)43, Assert.Single(cached.Answers).GetData()[3]);
        Assert.Equal(2, fixture.Source.Calls);
    }

    [Fact]
    public async Task DeadlineCancelsWaitersWhileIgnoringProviderRemainsOwned()
    {
        var fixture = new RecursiveCacheFixture(maximumFlights: 1, resolutionTimeout: TimeSpan.FromSeconds(1));
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var query = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var call = await fixture.Source.NextAsync().ConfigureAwait(true);
        fixture.Clock.Set(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => query.WaitAsync(RecursiveCacheFixture.Timeout)).ConfigureAwait(true);
        Assert.True(call.Token.IsCancellationRequested);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(2, (await fixture.Cache.ResolveAsync(Question, CancellationToken.None).ConfigureAwait(true)).ResponseCode);
        var drain = fixture.Cache.DisposeAsync().AsTask();
        Assert.False(drain.IsCompleted);
        call.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30));
        await drain.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
    }

    [Fact]
    public async Task DisposalCancelsEveryWaiterAndJoinsIgnoringProviderBeforeTerminalCompletion()
    {
        var fixture = new RecursiveCacheFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var first = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var second = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var call = await fixture.Source.NextAsync().ConfigureAwait(true);
        var drain = fixture.Cache.DisposeAsync().AsTask();
        var repeated = fixture.Cache.DisposeAsync().AsTask();
        Assert.Same(drain, repeated);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(RecursiveCacheFixture.Timeout)).ConfigureAwait(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second.WaitAsync(RecursiveCacheFixture.Timeout)).ConfigureAwait(true);
        Assert.True(call.Token.IsCancellationRequested);
        Assert.False(drain.IsCompleted);
        Assert.Equal(1, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(0, fixture.Cache.Statistics.Waiters);
        _ = await Assert.ThrowsAsync<ObjectDisposedException>(() => fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask()).ConfigureAwait(true);
        Assert.Throws<ObjectDisposedException>(fixture.Cache.Clear);
        call.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30));
        await drain.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.PayloadBytes);
        Assert.Equal(0, fixture.Cache.Statistics.ActiveFlights);
        Assert.Equal(0, fixture.Clock.ActiveTimers);
    }

    [Fact]
    public async Task ProviderFailureIsDeliveredWithoutPoisoningAdmissionOrCache()
    {
        var fixture = new RecursiveCacheFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var query = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var failure = await fixture.Source.NextAsync().ConfigureAwait(true);
        failure.Completion.SetException(new IOException("Controlled failed resolution."));
        await Assert.ThrowsAsync<IOException>(() => query.WaitAsync(RecursiveCacheFixture.Timeout)).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.ActiveFlights);
        var retry = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var success = await fixture.Source.NextAsync().ConfigureAwait(true);
        success.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30));
        _ = await retry.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(2, fixture.Source.Calls);
        Assert.Equal(1, fixture.Cache.Statistics.Entries);
    }

    [Fact]
    public async Task FreshZeroTtlPositiveInvalidatesContradictoryNameWideNegative()
    {
        var fixture = new RecursiveCacheFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var positive = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var positiveCall = await fixture.Source.NextAsync().ConfigureAwait(true);
        var negative = fixture.Cache.ResolveAsync(Question with { Type = 28 }, CancellationToken.None).AsTask();
        var negativeCall = await fixture.Source.NextAsync().ConfigureAwait(true);
        negativeCall.Completion.SetResult(RecursiveCacheTests.Negative(3, 30, 30));
        _ = await negative.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(1, fixture.Cache.Statistics.Entries);
        positiveCall.Completion.SetResult(RecursiveCacheTests.Positive(Question, 0));
        _ = await positive.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
        var fresh = fixture.Cache.ResolveAsync(Question with { Type = 28 }, CancellationToken.None).AsTask();
        var third = await fixture.Source.NextAsync().ConfigureAwait(true);
        third.Completion.SetResult(RecursiveCacheTests.Negative(0, 30, 30));
        _ = await fresh.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(3, fixture.Source.Calls);
    }

    [Fact]
    public async Task FreshZeroTtlNxdomainInvalidatesConflictingPositiveEntries()
    {
        var fixture = new RecursiveCacheFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var negative = fixture.Cache.ResolveAsync(Question with { Type = 28 }, CancellationToken.None).AsTask();
        var negativeCall = await fixture.Source.NextAsync().ConfigureAwait(true);
        var positive = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var positiveCall = await fixture.Source.NextAsync().ConfigureAwait(true);
        positiveCall.Completion.SetResult(RecursiveCacheTests.Positive(Question, 30));
        _ = await positive.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(1, fixture.Cache.Statistics.Entries);
        negativeCall.Completion.SetResult(RecursiveCacheTests.Negative(3, 30, 0));
        _ = await negative.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
    }

    [Fact]
    public async Task AnUncacheablePositiveStillInvalidatesNameWideAbsence()
    {
        var fixture = new RecursiveCacheFixture();
        await using var fixtureLifetime = fixture.ConfigureAwait(true);
        var positive = fixture.Cache.ResolveAsync(Question, CancellationToken.None).AsTask();
        var positiveCall = await fixture.Source.NextAsync().ConfigureAwait(true);
        var negative = fixture.Cache.ResolveAsync(Question with { Type = 28 }, CancellationToken.None).AsTask();
        var negativeCall = await fixture.Source.NextAsync().ConfigureAwait(true);
        negativeCall.Completion.SetResult(RecursiveCacheTests.Negative(3, 30, 30));
        _ = await negative.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        positiveCall.Completion.SetResult(new DnsAnswer(0, false,
            Enumerable.Range(0, 513).Select(_ => new DnsRecord(Question.Name, 1, 30, new byte[] { 192, 0, 2, 42 })), [], []));
        _ = await positive.WaitAsync(RecursiveCacheFixture.Timeout).ConfigureAwait(true);
        Assert.Equal(0, fixture.Cache.Statistics.Entries);
    }

    [Fact]
    public async Task PrecanceledRequestsNeverRegisterAndCacheDoesNotDisposeCallerOwnedProvider()
    {
        var source = new RecursiveCacheFixture.ImmediateResolver(q => RecursiveCacheTests.Positive(q, 30));
        await using var sourceLifetime = source.ConfigureAwait(true);
        var cache = new CachingRecursiveResolver(source);
        using var canceled = new CancellationTokenSource();
        await canceled.CancelAsync().ConfigureAwait(true);
        _ = await Assert.ThrowsAsync<OperationCanceledException>(() => cache.ResolveAsync(Question, canceled.Token).AsTask()).ConfigureAwait(true);
        Assert.Equal(0, source.Calls);
        await cache.DisposeAsync().ConfigureAwait(true);
        Assert.False(source.Disposed);
        Assert.Equal(0, cache.Statistics.Waiters);
    }
}
