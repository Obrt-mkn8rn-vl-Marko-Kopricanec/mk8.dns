using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class DnssecFailureCacheLifecycleTests
{
    [Fact]
    public async Task FailureHitsNeedNoRequestSlotWhileAnotherProviderRemainsAdmitted()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(), maximumRequests: 1);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (_, _, _) => new ValueTask<DnsUpstreamEvidence>(held.Task);
        var other = cache.ResolveDnssecAsync(question with { Name = DnsName.Parse("other.example.") }, CancellationToken.None).AsTask();
        try
        {
            DnssecFailureCacheTests.AssertFailure(await cache.ResolveDnssecAsync(question, CancellationToken.None));
            Assert.Equal(1, cache.Statistics.ActiveRequests);
            Assert.Equal(0, cache.Statistics.AdmissionRejections);
            Assert.Equal(1, cache.FailureStatistics.Hits);
            Assert.Equal(2, fixture.Calls.Count);
        }
        finally { held.TrySetException(new TimeoutException()); }
        await other.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true);
    }

    [Fact]
    public async Task CallerCancellationRetainsActualSourceOwnershipAndNeverCaches()
    {
        using var fixture = new OnlineDnssecFixture();
        using var cancellation = new CancellationTokenSource();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (_, _, _) => new ValueTask<DnsUpstreamEvidence>(held.Task);
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(), maximumRequests: 1);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        var operation = cache.ResolveDnssecAsync(question, cancellation.Token).AsTask();
        try
        {
            await cancellation.CancelAsync().ConfigureAwait(true);
            Assert.False(operation.IsCompleted);
            Assert.Equal(1, cache.Statistics.ActiveRequests);
            DnssecFailureCacheTests.AssertFailure(await cache.ResolveDnssecAsync(question, CancellationToken.None));
            Assert.Equal(0, cache.FailureStatistics.Stores);
        }
        finally
        {
            held.TrySetResult(fixture.Default(new DnsQuestion(fixture.Root, 48, 1), OnlineDnssecFixture.RootServer));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5))).ConfigureAwait(true);
        }
        Assert.Equal(0, cache.Statistics.ActiveRequests);
        Assert.Equal(0, cache.FailureStatistics.Entries);
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(2, fixture.Calls.Count);
        Assert.Equal(1, cache.FailureStatistics.Stores);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClearAndDisposalFencePendingFailuresButJoinTheSource(bool dispose)
    {
        using var fixture = new OnlineDnssecFixture();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (_, _, _) => new ValueTask<DnsUpstreamEvidence>(held.Task);
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        var operation = cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None).AsTask();
        Task? closure = null;
        try
        {
            if (dispose) closure = cache.DisposeAsync().AsTask();
            else cache.Clear();
            Assert.False(operation.IsCompleted);
            Assert.Equal(1, cache.Statistics.ActiveRequests);
            if (closure is not null) Assert.False(closure.IsCompleted);
        }
        finally
        {
            held.TrySetException(new TimeoutException());
            DnssecFailureCacheTests.AssertFailure(await operation.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true));
            await cache.DisposeAsync().ConfigureAwait(true);
        }
        Assert.Equal(0, cache.Statistics.ActiveRequests);
        Assert.Equal(0, cache.FailureStatistics.Entries);
        Assert.Equal(0, cache.FailureStatistics.Stores);
    }

    [Fact]
    public async Task ProviderFaultIsPropagatedRatherThanCachedAsResolutionFailure()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new InvalidOperationException("Controlled provider fault."));
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        for (var index = 0; index < 2; index++)
            await Assert.ThrowsAsync<InvalidOperationException>(() => cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None).AsTask());
        Assert.Equal(2, fixture.Calls.Count);
        Assert.Equal(0, cache.Statistics.ActiveRequests);
        Assert.Equal(0, cache.FailureStatistics.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OlderAdmittedFailureCannotReplaceNewerSuccessOrRestartNewerHoldDown(bool newerSucceeds)
    {
        using var fixture = new OnlineDnssecFixture();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (_, _, _) => new ValueTask<DnsUpstreamEvidence>(held.Task);
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(minimumTtl: 2, maximumTtl: 2));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        var older = cache.ResolveDnssecAsync(question, CancellationToken.None).AsTask();
        try
        {
            fixture.Override = newerSucceeds ? null : (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
            await cache.ResolveDnssecAsync(question, CancellationToken.None);
            fixture.Clock.Advance(1);
        }
        finally { held.TrySetException(new TimeoutException()); }
        DnssecFailureCacheTests.AssertFailure(await older.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true));
        var calls = fixture.Calls.Count;
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(newerSucceeds ? 0 : 1, cache.FailureStatistics.Stores);
        fixture.Clock.Advance(1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(newerSucceeds ? calls : calls + 1, fixture.Calls.Count);
    }

    [Fact]
    public async Task ConcurrentDifferentTypeCannotSuppressAnActualFailedQuestionStore()
    {
        using var fixture = new OnlineDnssecFixture();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (_, _, _) => new ValueTask<DnsUpstreamEvidence>(held.Task);
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy());
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        var earlier = cache.ResolveDnssecAsync(question, CancellationToken.None).AsTask();
        try
        {
            fixture.Override = null;
            Assert.Equal(DnssecResolutionOutcome.Authenticated, (await cache.ResolveDnssecAsync(question with { Type = 28 }, CancellationToken.None)).Outcome);
        }
        finally { held.TrySetException(new TimeoutException()); }
        await earlier.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true);
        var calls = fixture.Calls.Count;
        DnssecFailureCacheTests.AssertFailure(await cache.ResolveDnssecAsync(question, CancellationToken.None));
        Assert.Equal(calls, fixture.Calls.Count);
        Assert.Equal(1, cache.FailureStatistics.Entries);
    }

    [Fact]
    public async Task ClearRemovesHoldDownAndBackoffHistory()
    {
        using var fixture = new OnlineDnssecFixture();
        fixture.Override = (_, _, _) => ValueTask.FromException<DnsUpstreamEvidence>(new TimeoutException());
        var cache = CachingDnssecResolver.CreateWithFailureCache(fixture.Resolver(), new DnssecFailureCachePolicy(minimumTtl: 1, maximumTtl: 4));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        cache.Clear();
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        fixture.Clock.Advance(1);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(4, fixture.Calls.Count);
    }
}
