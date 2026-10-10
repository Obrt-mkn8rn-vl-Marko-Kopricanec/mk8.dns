using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class CoalescingDnssecResolver
{
    private async Task RunAsync(DnssecWorkFlight flight)
    {
        // Leave admission before calling any caller-owned source/provider code.
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        var execution = ExecuteAsync(flight);
        try
        {
            var delivery = await execution.ConfigureAwait(false);
            lock (gate)
            {
                if (closing || flight.Abandoned || flight.Token.IsCancellationRequested) flight.Completion.TrySetCanceled(new CancellationToken(canceled: true));
                else flight.Completion.TrySetResult(delivery);
            }
        }
        catch (Exception error) when (execution.IsFaulted || execution.IsCanceled)
        {
            lock (gate)
            {
                if (closing || flight.Abandoned || flight.Token.IsCancellationRequested) flight.Completion.TrySetCanceled(new CancellationToken(canceled: true));
                else flight.Completion.TrySetException(error);
            }
        }
        finally { lock (gate) { workers.Remove(flight); RemovePending(flight); sharedBudget?.Release(); } }
        if (flight.Completion.Task.IsFaulted) _ = flight.Completion.Task.Exception;
    }

    private async Task<DnssecWorkFlight.Delivery> ExecuteAsync(DnssecWorkFlight flight)
    {
        DnssecWorkFlight.Delivery delivery;
        Exception? cleanupError;
        try
        {
            flight.Token.ThrowIfCancellationRequested();
            var result = await source.ResolveDnssecAsync(flight.Question, flight.Token).ConfigureAwait(false);
            flight.Token.ThrowIfCancellationRequested();
            delivery = new DnssecWorkFlight.Delivery(result, clock.GetTimestamp());
        }
        finally
        {
            cleanupError = await CleanupAsync(flight).ConfigureAwait(false);
        }
        if (cleanupError is not null) throw new InvalidOperationException("Authenticated cancellation cleanup failed.", cleanupError);
        return delivery;
    }

    private async ValueTask<Exception?> CleanupAsync(DnssecWorkFlight flight)
    {
        var cleanup = flight.DisposeAsync().AsTask();
        try { await cleanup.ConfigureAwait(false); return null; }
        catch (Exception error) when (cleanup.IsFaulted || cleanup.IsCanceled)
        {
            lock (gate) cleanupFailure ??= error;
            return error;
        }
    }

    private DnssecResolutionResult Deliver(DnssecWorkFlight.Delivery delivery)
    {
        var result = delivery.Result;
        if (result.Outcome != DnssecResolutionOutcome.Authenticated) return result;
        if (result.Lease?.IsValid() != true) return DnssecResolutionWork.Failure(result.Question);
        var now = clock.GetTimestamp();
        var ttl = Math.Min(result.Lease.Remaining(), clock.Age(result.AuthenticatedTtl, delivery.Received, now));
        if (source.RetainsClientProof)
            return CachingDnssecResolver.PrepareClientProofDelivery(result, ttl) ?? DnssecResolutionWork.Failure(result.Question);
        DnsRecord[] Age(IReadOnlyList<DnsRecord> records) => [.. records.Select(record => record.WithTtl(Math.Min(ttl, clock.Age(record.Ttl, delivery.Received, now))))];
        return new DnssecResolutionResult(result.Question, result.Outcome, result.ResponseCode, result.Origin,
            result.UnsignedDelegation, ttl, Age(result.Answers), Age(result.Authority), result.Lease);
    }

    private async Task FinishDisposalAsync(DnssecWorkFlight[] active)
    {
        var drain = DrainAsync(active);
        try { await drain.ConfigureAwait(false); disposed.TrySetResult(); }
        catch (Exception error) when (drain.IsFaulted || drain.IsCanceled) { disposed.TrySetException(error); }
    }

    private async Task DrainAsync(DnssecWorkFlight[] active)
    {
        await Task.WhenAll(active.Select(flight => flight.Worker)).ConfigureAwait(false);
        await waitersDrained.Task.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        if (cleanupFailure is not null) throw new InvalidOperationException("Authenticated cancellation cleanup failed.", cleanupFailure);
    }
}
