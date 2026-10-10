using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Xunit;

namespace Mk8.Dns.UnitTests;

public sealed class ClientProofCacheLifecycleTests
{
    [Fact]
    public async Task RequestQuotaRemainsOwnedUntilIgnoringProviderActuallyReturns()
    {
        using var fixture = new OnlineDnssecFixture();
        using var cancellation = new CancellationTokenSource();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (_, _, _) => new ValueTask<DnsUpstreamEvidence>(held.Task);
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture), maximumRequests: 1);
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var request = cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), cancellation.Token).AsTask();
        try
        {
            Assert.Equal(1, cache.Statistics.ActiveRequests);
            await cancellation.CancelAsync().ConfigureAwait(true);
            Assert.False(request.IsCompleted);
            Assert.Equal(DnssecResolutionOutcome.Failure,
                (await cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question("other.example."), CancellationToken.None)).Outcome);
            Assert.Equal(1, cache.Statistics.AdmissionRejections);
            Assert.Single(fixture.Calls);
        }
        finally
        {
            held.TrySetResult(fixture.Default(new DnsQuestion(fixture.Root, 48, 1), OnlineDnssecFixture.RootServer));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
        }
        Assert.Equal(0, cache.Statistics.ActiveRequests);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharedDisposalClosesAdmissionAndDrainsSuccessOrFault(bool fault)
    {
        using var fixture = new OnlineDnssecFixture();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (question, server, _) => question.Type == 48
            ? new ValueTask<DnsUpstreamEvidence>(held.Task) : ValueTask.FromResult(fixture.Default(question, server));
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture));
        var operation = cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None).AsTask();
        var first = cache.DisposeAsync().AsTask();
        var second = cache.DisposeAsync().AsTask();
        try
        {
            Assert.Same(first, second);
            Assert.False(first.IsCompleted);
            Assert.Equal(1, cache.Statistics.ActiveRequests);
            await Assert.ThrowsAsync<ObjectDisposedException>(() => cache.ResolveDnssecAsync(DnssecCacheResolutionTests.Question(), CancellationToken.None).AsTask());
            Assert.Throws<ObjectDisposedException>(cache.Clear);
        }
        finally
        {
            if (fault) held.TrySetException(new InvalidOperationException("Controlled provider failure."));
            else held.TrySetResult(fixture.Default(new DnsQuestion(fixture.Root, 48, 1), OnlineDnssecFixture.RootServer));
            if (fault) await Assert.ThrowsAsync<InvalidOperationException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None)).ConfigureAwait(true);
            else Assert.Equal(DnssecResolutionOutcome.Authenticated, (await operation.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
            await first.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
        }
        Assert.Equal(0, cache.Statistics.ActiveRequests);
        Assert.Equal(0, cache.Statistics.Entries);
    }

    [Fact]
    public async Task ClearFencesPendingStoreWithoutDetachingProvider()
    {
        using var fixture = new OnlineDnssecFixture();
        var held = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Override = (question, server, _) => question.Type == 48 && fixture.Calls.Count == 1
            ? new ValueTask<DnsUpstreamEvidence>(held.Task) : ValueTask.FromResult(fixture.Default(question, server));
        var cache = CachingDnssecResolver.CreateWithClientProofCache(ClientProofFixture.Resolver(fixture));
        await using var cacheLifetime = cache.ConfigureAwait(true);
        var question = DnssecCacheResolutionTests.Question();
        var operation = cache.ResolveDnssecAsync(question, CancellationToken.None).AsTask();
        try
        {
            cache.Clear();
            Assert.False(operation.IsCompleted);
            Assert.Equal(1, cache.Statistics.ActiveRequests);
        }
        finally { held.TrySetResult(fixture.Default(new DnsQuestion(fixture.Root, 48, 1), OnlineDnssecFixture.RootServer)); }
        Assert.Equal(DnssecResolutionOutcome.Authenticated, (await operation.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, CancellationToken.None).ConfigureAwait(true)).Outcome);
        Assert.Equal(0, cache.Statistics.Entries);
        await cache.ResolveDnssecAsync(question, CancellationToken.None);
        Assert.Equal(4, fixture.Calls.Count);
        Assert.Equal(1, cache.Statistics.Entries);
    }
}
