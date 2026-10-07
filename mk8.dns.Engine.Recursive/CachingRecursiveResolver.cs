using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed class CachingRecursiveResolver : IDnsResolver, IAsyncDisposable
{
    private readonly Lock gate = new();
    private readonly IDnsResolver resolver;
    private readonly TimeProvider time;
    private readonly RecursiveCachePolicy policy;
    private readonly TimeSpan resolutionTimeout;
    private readonly int maximumEntries;
    private readonly long maximumPayloadBytes;
    private readonly int maximumFlights;
    private readonly int maximumWaiters;
    private readonly Dictionary<DnsQuestion, LinkedListNode<Entry>> entries = [];
    private readonly Dictionary<(DnsName Name, ushort Class), HashSet<DnsQuestion>> names = [];
    private readonly LinkedList<Entry> recent = new();
    private readonly Dictionary<DnsQuestion, RecursiveCacheFlight> pending = [];
    private readonly HashSet<RecursiveCacheFlight> workers = [];
    private readonly TaskCompletionSource waitersDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? disposalWorker;
    private Exception? cleanupFailure;
    private bool closing;
    private bool clockStarted;
    private long latestTimestamp;
    private long generation;
    private long payloadBytes;
    private int waiters;
    private long hits;
    private long misses;
    private long coalesced;
    private long admissionRejections;
    private long evictions;
    private long expirations;

    public CachingRecursiveResolver(IDnsResolver resolver, int maximumEntries = 4096, long maximumPayloadBytes = 16777216,
        int maximumFlights = 64, int maximumWaiters = 1024, uint maximumPositiveTtl = 86400, uint maximumNegativeTtl = 3600,
        TimeSpan? resolutionTimeout = null, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        if (maximumEntries is < 1 or > 65536 || maximumPayloadBytes is < 1 or > 536870912
            || maximumFlights is < 1 or > 256 || maximumWaiters is < 1 or > 65536
            || maximumPositiveTtl is < 1 or > 604800 || maximumNegativeTtl is < 1 or > 86400 || maximumNegativeTtl > maximumPositiveTtl)
            throw new ArgumentOutOfRangeException(nameof(maximumEntries), "Invalid recursive cache limits.");
        this.resolutionTimeout = resolutionTimeout ?? TimeSpan.FromSeconds(10);
        if (this.resolutionTimeout < TimeSpan.FromMilliseconds(50) || this.resolutionTimeout > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(resolutionTimeout));
        this.resolver = resolver;
        this.time = time ?? TimeProvider.System;
        policy = new RecursiveCachePolicy(maximumPositiveTtl, maximumNegativeTtl);
        this.maximumEntries = maximumEntries;
        this.maximumPayloadBytes = maximumPayloadBytes;
        this.maximumFlights = maximumFlights;
        this.maximumWaiters = maximumWaiters;
    }

    public ValueTask<DnsAnswer> ResolveAsync(DnsQuestion question, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(question);
        if (question.Name is null)
            throw new ArgumentException("A recursive question needs a name.", nameof(question));
        cancellationToken.ThrowIfCancellationRequested();
        RecursiveCacheFlight flight;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            if (!RecursiveCachePolicy.Supports(question))
                return ValueTask.FromResult(Empty(5));
            var cached = ReadCached(question);
            if (cached is not null)
                return ValueTask.FromResult(cached);
            misses++;
            if (pending.TryGetValue(question, out var canceledFlight) && canceledFlight.Token.IsCancellationRequested)
                RemovePending(canceledFlight);
            if (waiters == maximumWaiters || !pending.ContainsKey(question) && workers.Count == maximumFlights)
            {
                admissionRejections++;
                return ValueTask.FromResult(Empty(2));
            }
            if (pending.TryGetValue(question, out var existing))
            {
                flight = existing;
                coalesced++;
            }
            else
            {
                flight = new RecursiveCacheFlight(question, generation, time, resolutionTimeout);
                pending.Add(question, flight);
                workers.Add(flight);
                flight.Worker = RunFlightAsync(flight);
            }
            waiters++;
            flight.Waiters++;
        }
        return AwaitFlightAsync(flight, cancellationToken);
    }

    public RecursiveCacheStatistics Statistics
    {
        get
        {
            lock (gate)
                return new RecursiveCacheStatistics(entries.Count, payloadBytes, workers.Count, waiters, hits, misses, coalesced, admissionRejections, evictions, expirations);
        }
    }

    public void Clear()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(closing, this);
            generation = checked(generation + 1);
            ClearEntries();
            // Old work remains owned, but new callers cannot join it or cache its result.
            pending.Clear();
        }
    }

    public ValueTask DisposeAsync()
    {
        RecursiveCacheFlight[] active;
        lock (gate)
        {
            if (closing || disposalWorker is not null)
                return new ValueTask(disposed.Task);
            closing = true;
            ClearEntries();
            pending.Clear();
            active = workers.ToArray();
            foreach (var flight in active) flight.Abandoned = true;
            if (waiters == 0) waitersDrained.TrySetResult();
        }
        foreach (var flight in active) flight.Cancel();
        lock (gate) disposalWorker = FinishDisposalAsync(active);
        return new ValueTask(disposed.Task);
    }

    private async ValueTask<DnsAnswer> AwaitFlightAsync(RecursiveCacheFlight flight, CancellationToken cancellationToken)
    {
        try
        {
            var result = await flight.Completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (closing) throw new OperationCanceledException("The recursive cache is closing.");
                return Age(result.Answer, AgeSeconds(result.Received, Now()));
            }
        }
        finally
        {
            var cancel = false;
            lock (gate)
            {
                waiters--;
                flight.Waiters--;
                if (flight.Waiters == 0 && workers.Contains(flight))
                {
                    flight.Abandoned = true;
                    RemovePending(flight);
                    cancel = true;
                }
                if (closing && waiters == 0) waitersDrained.TrySetResult();
            }
            if (cancel) flight.Cancel();
        }
    }

    private async Task RunFlightAsync(RecursiveCacheFlight flight)
    {
        // Always leave the admission stack before invoking caller-owned resolver code.
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        var execution = ExecuteFlightAsync(flight);
        try
        {
            var result = await execution.ConfigureAwait(false);
            lock (gate)
            {
                if (closing || flight.Abandoned || flight.Token.IsCancellationRequested)
                    flight.Completion.TrySetCanceled(new CancellationToken(canceled: true));
                else
                    flight.Completion.TrySetResult(result);
            }
        }
        catch (Exception error) when (execution.IsFaulted || execution.IsCanceled)
        {
            // Convert only the owned execution's terminal fault into the shared reply.
            lock (gate)
            {
                if (closing || flight.Abandoned || flight.Token.IsCancellationRequested)
                    flight.Completion.TrySetCanceled(new CancellationToken(canceled: true));
                else
                    flight.Completion.TrySetException(error);
            }
        }
        finally
        {
            lock (gate)
            {
                workers.Remove(flight);
                RemovePending(flight);
            }
        }
        // Reading Exception observes the shared terminal fault even if every waiter left.
        if (flight.Completion.Task.IsFaulted)
            _ = flight.Completion.Task.Exception;
    }

    private async Task<RecursiveCacheResult> ExecuteFlightAsync(RecursiveCacheFlight flight)
    {
        Produced produced;
        Exception? cleanupError = null;
        try
        {
            produced = await ProduceAsync(flight).ConfigureAwait(false);
        }
        finally
        {
            // Preserve a provider fault even if cleanup also fails; disposal reports cleanup separately.
            cleanupError = await CleanupAsync(flight).ConfigureAwait(false);
        }
        if (cleanupError is not null)
            throw new InvalidOperationException("Recursive cancellation cleanup failed.", cleanupError);
        var result = produced.Result;
        lock (gate)
        {
            if (closing || flight.Abandoned || flight.Token.IsCancellationRequested)
                throw new OperationCanceledException("The recursive resolution was abandoned.", flight.Token);
            if (flight.Generation == generation)
            {
                if (RecursiveCachePolicy.ProvesNameExists(flight.Question, result.Answer)
                    && entries.TryGetValue(flight.Question with { Type = 0 }, out var absence))
                    Remove(absence);
                if (produced.Candidate is not null) Store(flight.Question, produced.Candidate, result.Received);
            }
        }
        return result;
    }

    private async Task<Produced> ProduceAsync(RecursiveCacheFlight flight)
    {
        flight.Token.ThrowIfCancellationRequested();
        var answer = await resolver.ResolveAsync(flight.Question, flight.Token).ConfigureAwait(false);
        flight.Token.ThrowIfCancellationRequested();
        long received;
        lock (gate) received = Now();
        var candidate = policy.Prepare(flight.Question, answer);
        return new Produced(new RecursiveCacheResult(candidate?.Answer ?? answer, received), candidate);
    }

    private async ValueTask<Exception?> CleanupAsync(RecursiveCacheFlight flight)
    {
        var cleanup = flight.DisposeAsync().AsTask();
        try
        {
            await cleanup.ConfigureAwait(false);
            return null;
        }
        catch (Exception error) when (cleanup.IsFaulted || cleanup.IsCanceled)
        {
            lock (gate) cleanupFailure ??= error;
            return error;
        }
    }

    private async Task FinishDisposalAsync(RecursiveCacheFlight[] active)
    {
        var drain = DrainAsync(active);
        try
        {
            await drain.ConfigureAwait(false);
            disposed.TrySetResult();
        }
        catch (Exception error) when (drain.IsFaulted || drain.IsCanceled)
        {
            disposed.TrySetException(error);
        }
    }

    private async Task DrainAsync(RecursiveCacheFlight[] active)
    {
        await Task.WhenAll(active.Select(flight => flight.Worker)).ConfigureAwait(false);
        await waitersDrained.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        if (cleanupFailure is not null)
            throw new InvalidOperationException("Recursive cancellation cleanup failed.", cleanupFailure);
    }

    private DnsAnswer? ReadCached(DnsQuestion question)
    {
        var now = Now();
        foreach (var key in new[] { question, question with { Type = 0 } })
        {
            if (!entries.TryGetValue(key, out var node)) continue;
            var age = AgeSeconds(node.Value.Received, now);
            if (age >= node.Value.Lifetime)
            {
                Remove(node);
                expirations++;
                continue;
            }
            recent.Remove(node);
            recent.AddLast(node);
            hits++;
            return Age(node.Value.Answer, age);
        }
        return null;
    }

    private void Store(DnsQuestion question, RecursiveCacheCandidate candidate, long received)
    {
        var key = candidate.NameWide ? question with { Type = 0 } : question;
        var name = (key.Name, key.Class);
        if (candidate.NameWide && names.TryGetValue(name, out var conflicting))
            foreach (var old in conflicting.ToArray()) Remove(entries[old]);
        else if (entries.TryGetValue(question with { Type = 0 }, out var negative))
            Remove(negative);
        if (entries.TryGetValue(key, out var previous)) Remove(previous);
        if (candidate.Lifetime == 0 || candidate.PayloadBytes > maximumPayloadBytes || candidate.PayloadBytes > 65535
            || AgeSeconds(received, Now()) >= candidate.Lifetime)
            return;
        while (entries.Count >= maximumEntries || payloadBytes + candidate.PayloadBytes > maximumPayloadBytes)
        {
            Remove(recent.First!);
            evictions++;
        }
        var node = recent.AddLast(new Entry(key, candidate.Answer, received, candidate.Lifetime, candidate.PayloadBytes));
        entries.Add(key, node);
        if (!names.TryGetValue(name, out var keys)) names.Add(name, keys = []);
        keys.Add(key);
        payloadBytes += candidate.PayloadBytes;
    }

    private void Remove(LinkedListNode<Entry> node)
    {
        var entry = node.Value;
        entries.Remove(entry.Key);
        recent.Remove(node);
        payloadBytes -= entry.PayloadBytes;
        var name = (entry.Key.Name, entry.Key.Class);
        var keys = names[name];
        keys.Remove(entry.Key);
        if (keys.Count == 0) names.Remove(name);
    }

    private void RemovePending(RecursiveCacheFlight flight)
    {
        if (pending.TryGetValue(flight.Question, out var current) && ReferenceEquals(current, flight))
            pending.Remove(flight.Question);
    }

    private void ClearEntries()
    {
        entries.Clear();
        names.Clear();
        recent.Clear();
        payloadBytes = 0;
    }

    private long Now()
    {
        var current = time.GetTimestamp();
        if (!clockStarted || current > latestTimestamp) latestTimestamp = current;
        clockStarted = true;
        return latestTimestamp;
    }

    private double AgeSeconds(long received, long now) => Math.Ceiling(Math.Max(0, time.GetElapsedTime(received, now).TotalSeconds));
    private static DnsAnswer Age(DnsAnswer answer, double age) => new(answer.ResponseCode, false,
        answer.Answers.Select(record => record.WithTtl(age >= record.Ttl ? 0 : record.Ttl - (uint)age)),
        answer.Authority.Select(record => record.WithTtl(age >= record.Ttl ? 0 : record.Ttl - (uint)age)), []);
    private static DnsAnswer Empty(byte code) => new(code, false, [], [], []);
    private sealed record Entry(DnsQuestion Key, DnsAnswer Answer, long Received, uint Lifetime, long PayloadBytes);
    private sealed record Produced(RecursiveCacheResult Result, RecursiveCacheCandidate? Candidate);
}
