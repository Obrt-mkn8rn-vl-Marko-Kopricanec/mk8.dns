using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Recursive;

namespace Mk8.Dns.UnitTests;

internal sealed class CoalescedTrustEpochFixture : IAsyncDisposable
{
    private readonly List<(TaskCompletionSource<DnsUpstreamEvidence> Held, DnsUpstreamEvidence Reply)> held = [];
    internal CoalescedTrustEpochFixture(int workers = 2, int waiters = 8, int requests = 8, bool failureCache = false)
    {
        Clock = new WorkClock(Data);
        Resolver = DnssecTrustEpochResolver.CreateWithCoalescing(Data.Refresh, new Source(this), Data.Verifier,
            [AnchorRefreshFixture.Server], new DnssecTrustEpochPolicy(maximumActiveRequests: requests,
                failureCache: failureCache ? new DnssecFailureCachePolicy() : null),
            new DnssecWorkPolicy(workers, waiters, TimeSpan.FromSeconds(1)), Clock);
    }

    internal TrustEpochFixture Data { get; } = new();
    internal DnssecTrustEpochResolver Resolver { get; }
    internal WorkClock Clock { get; }
    internal DnsQuestion Question => Data.Question;
    internal Func<DnsQuestion, DnsServerEndpoint, CancellationToken, ValueTask<DnsUpstreamEvidence>>? Override { get; set; }
    internal TaskCompletionSource<DnsUpstreamEvidence> Hold(DnsQuestion question)
    {
        var result = new TaskCompletionSource<DnsUpstreamEvidence>(TaskCreationOptions.RunContinuationsAsynchronously);
        held.Add((result, Default(question, AnchorRefreshFixture.Server)));
        return result;
    }
    internal DnsUpstreamEvidence Default(DnsQuestion question, DnsServerEndpoint server)
    {
        if (question.Type == 48) return Data.Default(question, server);
        // Reserved documentation bytes are controlled signed fixture inputs, not allocations.
        byte[] bytes = question.Type == 28 ? [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, Data.LastOctet]
            : [192, 0, 2, Data.LastOctet];
        var record = new DnsRecord(question.Name, question.Type, Data.DataTtl, bytes);
        return Data.Anchors.Reply(question, server, answers: [record, Data.Sign([record])]);
    }

    internal static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var guard = new CancellationTokenSource(AnchorRefreshFixture.Timeout);
        while (!condition()) await Task.Delay(1, guard.Token).ConfigureAwait(true);
    }

    public async ValueTask DisposeAsync()
    {
        Clock.DisposalReleased.TrySetResult();
        var closing = Resolver.DisposeAsync().AsTask();
        foreach (var (Held, Reply) in held) Held.TrySetResult(Reply);
        try { await closing.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true); }
        finally { await Data.DisposeAsync().ConfigureAwait(true); }
    }

    private sealed class Source(CoalescedTrustEpochFixture owner) : IDnssecUpstream
    {
        public ValueTask<DnsUpstreamEvidence> ExchangeDnssecAsync(DnsQuestion question, DnsServerEndpoint server, CancellationToken cancellationToken)
        {
            owner.Data.Calls.Enqueue(question);
            return owner.Override is null ? ValueTask.FromResult(owner.Default(question, server))
                : owner.Override(question, server, cancellationToken);
        }
    }

    internal sealed class WorkClock(TrustEpochFixture source) : TimeProvider
    {
        private readonly RecursiveCacheClock timers = new();
        internal bool HoldDisposal { get; set; }
        internal bool FailCreation { get; set; }
        internal int ActiveTimers => timers.ActiveTimers;
        internal TaskCompletionSource DisposalEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource DisposalReleased { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override long TimestampFrequency => source.Anchors.Keys.Clock.TimestampFrequency;
        public override long GetTimestamp() => source.Anchors.Keys.Clock.GetTimestamp();
        public override DateTimeOffset GetUtcNow() => source.Anchors.Keys.Clock.GetUtcNow();
        internal void Set(double seconds)
        {
            source.Anchors.Keys.Clock.SetMonotonic(seconds);
            source.Anchors.Keys.Clock.SetWall(100 + (long)seconds);
            timers.Set(TimeSpan.FromSeconds(seconds));
        }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            if (FailCreation) throw new IOException("Controlled epoch timer creation failure.");
            return new Timer(this, timers.CreateTimer(callback, state, dueTime, period), HoldDisposal);
        }
        private sealed class Timer(WorkClock owner, ITimer timer, bool hold) : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => timer.Change(dueTime, period);
            public void Dispose() => timer.Dispose();
            public async ValueTask DisposeAsync()
            {
                if (hold)
                {
                    owner.DisposalEntered.TrySetResult();
                    await owner.DisposalReleased.Task.WaitAsync(AnchorRefreshFixture.Timeout, TimeProvider.System, CancellationToken.None).ConfigureAwait(true);
                }
                await timer.DisposeAsync().ConfigureAwait(true);
            }
        }
    }
}
