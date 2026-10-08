using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class CachingDnssecResolver : IAsyncDisposable
{
    private readonly Lock gate = new();
    private readonly DnssecIterativeResolver resolver;
    private readonly int maximumEntries;
    private readonly long maximumPayloadBytes;
    private readonly int maximumRequests;
    private readonly uint maximumPositiveTtl;
    private readonly uint maximumNegativeTtl;
    private readonly Dictionary<DnsQuestion, LinkedListNode<Entry>> entries = [];
    private readonly Dictionary<(DnsName Name, ushort Class), NameState> names = [];
    private readonly LinkedList<Entry> recent = new();
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private long generation;
    private long sequence;
    private long payloadBytes;
    private int activeRequests;
    private bool closing;
    private long hits;
    private long misses;
    private long admissionRejections;
    private long evictions;
    private long expirations;

    public CachingDnssecResolver(DnssecIterativeResolver resolver, int maximumEntries = 4096, long maximumPayloadBytes = 16777216,
        int maximumRequests = 64, uint maximumPositiveTtl = 86400, uint maximumNegativeTtl = 3600)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        if (maximumEntries is < 1 or > 65536 || maximumPayloadBytes is < 1 or > 536870912 || maximumRequests is < 1 or > 256
            || maximumPositiveTtl is < 1 or > 604800 || maximumNegativeTtl is < 1 or > 86400 || maximumNegativeTtl > maximumPositiveTtl)
            throw new ArgumentOutOfRangeException(nameof(maximumEntries), "Invalid authenticated cache limits.");
        this.resolver = resolver; this.maximumEntries = maximumEntries; this.maximumPayloadBytes = maximumPayloadBytes;
        this.maximumRequests = maximumRequests; this.maximumPositiveTtl = maximumPositiveTtl; this.maximumNegativeTtl = maximumNegativeTtl;
    }

    public DnssecCacheStatistics Statistics
    {
        get { lock (gate) return new(entries.Count, payloadBytes, activeRequests, hits, misses, admissionRejections, evictions, expirations); }
    }

    public ValueTask<DnssecResolutionResult> ResolveDnssecAsync(DnsQuestion question, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (question.Name is null) throw new ArgumentException("An authenticated cache question needs a name.", nameof(question));
        cancellationToken.ThrowIfCancellationRequested();
        Request request;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            var cached = Read(question);
            if (cached is not null) return ValueTask.FromResult(cached);
            misses++;
            if (activeRequests == maximumRequests)
            {
                admissionRejections++; return ValueTask.FromResult(DnssecResolutionWork.Failure(question));
            }
            var identity = (question.Name, question.Class);
            if (!names.TryGetValue(identity, out var state)) names.Add(identity, state = new NameState());
            state.Latest = checked(++sequence); state.Active++;
            activeRequests++;
            request = new Request(question, generation, state.Latest);
        }
        return ProduceAsync(request, cancellationToken);
    }

    public void Clear()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            generation = checked(generation + 1);
            foreach (var node in recent.ToArray()) Remove(entries[node.Result.Question]);
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            if (!closing)
            {
                closing = true; generation = checked(generation + 1);
                foreach (var entry in recent.ToArray()) Remove(entries[entry.Result.Question]);
                if (activeRequests == 0) drained.TrySetResult();
            }
            return new ValueTask(drained.Task);
        }
    }

    private async ValueTask<DnssecResolutionResult> ProduceAsync(Request request, CancellationToken token)
    {
        try
        {
            var result = await resolver.ResolveDnssecAsync(request.Question, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (result.Outcome == DnssecResolutionOutcome.Authenticated)
                {
                    if (result.Lease is null || !result.Lease.IsValid()) return DnssecResolutionWork.Failure(request.Question);
                    result = Prepare(result);
                    var state = names[(request.Question.Name, request.Question.Class)];
                    if (!closing && request.Generation == generation && request.Sequence == state.Latest) Store(result);
                }
                return result;
            }
        }
        finally
        {
            lock (gate)
            {
                var identity = (request.Question.Name, request.Question.Class); var state = names[identity];
                state.Active--; activeRequests--; DropName(identity, state);
                if (closing && activeRequests == 0) drained.TrySetResult();
            }
        }
    }

    private sealed record Request(DnsQuestion Question, long Generation, long Sequence);
    private sealed record Entry(DnssecResolutionResult Result, long Received, uint Lifetime, long Bytes);
    private sealed class NameState
    {
        internal long Latest { get; set; }
        internal int Active { get; set; }
        internal HashSet<DnsQuestion> Questions { get; } = [];
    }
}
