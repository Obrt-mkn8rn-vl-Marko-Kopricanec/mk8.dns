using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;
using Mk8.Dns.Infrastructure;
using Xunit;

namespace Mk8.Dns.IntegrationTests;

public sealed class DnssecWorkTransportTests
{
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    public async Task ConcurrentConsumersShareRealAuthenticatedExchangeAndThenUseAcceptedCache(bool ipv6, bool tcp, bool corrupt)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var zones = new QnameMinimisationWireFixture(corrupt, deep: false);
        var root = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var rootLifetime = root.ConfigureAwait(true);
        var child = new RsaDnssecWireFixture.Node(ipv6, tcp, deadline.Token); await using var childLifetime = child.ConfigureAwait(true);
        root.Start(query => zones.Reply(query, child.Server, rootRole: true));
        child.Start(query => zones.Reply(query, child.Server, rootRole: false));
        var transport = new DnssecUpstreamClient(server => server.Equals(root.Server) || server.Equals(child.Server), TimeSpan.FromSeconds(3));
        var held = new HeldUpstream(transport);
        var iterative = DnssecIterativeResolver.CreateWithQnameMinimisation(held, QnameMinimisationWireFixture.Verifier, zones.Anchor,
            [root.Server], new DnsQnameMinimisationPolicy(), child.Server.Port, time: zones.Clock);
        var cache = new CachingDnssecResolver(iterative); await using var cacheLifetime = cache.ConfigureAwait(true);
        var resolver = new CoalescingDnssecResolver(cache, new DnssecWorkPolicy()); await using var resolverLifetime = resolver.ConfigureAwait(true);
        var question = new DnsQuestion(zones.Name, 1, 1);
        var first = resolver.ResolveDnssecAsync(question, deadline.Token).AsTask();
        await held.Entered.Task.WaitAsync(deadline.Token).ConfigureAwait(true);
        var second = resolver.ResolveDnssecAsync(question, deadline.Token).AsTask();
        try
        {
            Assert.Equal(1, resolver.Statistics.Workers); Assert.Equal(2, resolver.Statistics.Waiters);
            Assert.Equal(1, resolver.Statistics.Coalesced);
        }
        finally { held.Released.TrySetResult(); }
        var results = await Task.WhenAll(first, second).WaitAsync(deadline.Token).ConfigureAwait(true);
        Assert.All(results, result => Assert.Equal(corrupt ? DnssecResolutionOutcome.Failure : DnssecResolutionOutcome.Authenticated, result.Outcome));
        var calls = held.Calls;
        var next = await resolver.ResolveDnssecAsync(question, deadline.Token).ConfigureAwait(true);
        Assert.Equal(results[0].Outcome, next.Outcome);
        if (corrupt) { Assert.True(held.Calls > calls); Assert.Empty(next.Answers); Assert.Equal(0, cache.Statistics.Entries); }
        else { Assert.Equal(calls, held.Calls); Assert.Equal(new byte[] { 192, 0, 2, 43 }, Assert.Single(next.Answers).GetData()); }
        Assert.Equal(0, resolver.Statistics.Workers); Assert.Equal(0, resolver.Statistics.Waiters);
    }

    private sealed class HeldUpstream(IDnssecUpstream source) : IDnssecUpstream
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Released { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                Entered.TrySetResult();
                await Released.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            return await source.ExchangeDnssecAsync(question, server, cancellationToken).ConfigureAwait(false);
        }
    }
}
