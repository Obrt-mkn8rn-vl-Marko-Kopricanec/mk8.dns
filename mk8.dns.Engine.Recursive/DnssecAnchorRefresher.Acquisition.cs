using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Engine.Recursive;

public sealed partial class DnssecAnchorRefresher
{
    private async ValueTask<DnssecAnchorRefreshOutcome> RefreshCoreAsync(CancellationToken token)
    {
        // Yield out of admission before any caller-owned provider/storage code.
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        try
        {
            token.ThrowIfCancellationRequested();
            var next = tracker.CreateStagedTracker();
            var question = new DnsQuestion(tracker.Origin, 48, 1);
            var received = clock.GetTimestamp();
            var wall = clock.GetUtcNow();
            DnsUpstreamEvidence reply;
            try { reply = await upstream.ExchangeDnssecAsync(question, server, token).ConfigureAwait(false); }
            catch (Exception error) when (error is IOException or TimeoutException or FormatException)
            {
                token.ThrowIfCancellationRequested(); return DnssecAnchorRefreshOutcome.Refused;
            }
            token.ThrowIfCancellationRequested();
            if (reply?.Question.Equals(question) != true || !reply.Server.Equals(server)
                || !reply.Authoritative || reply.ResponseCode != 0 || (reply.HasEdns && reply.EdnsVersion != 0)
                || reply.Authority.Count != 0 || reply.Answers.Any(record => !record.Owner.Equals(question.Name)
                    || (record.Type != 48 && (record.Type != 46 || record.GetData() is not [0, 48, ..]))))
            {
                return DnssecAnchorRefreshOutcome.Refused;
            }

            var elapsed = Math.Ceiling(Math.Max(Math.Max(0, clock.GetElapsedTime(received, clock.GetTimestamp()).TotalSeconds),
                Math.Max(0, (clock.GetUtcNow() - wall).TotalSeconds)));
            DnsRecord Age(DnsRecord record) => record.WithTtl(elapsed >= record.Ttl ? 0 : record.Ttl - (uint)elapsed);
            var keys = reply.Answers.Where(record => record.Type == 48).Select(Age).ToArray();
            var signatures = reply.Answers.Where(record => record.Type == 46).Select(Age).ToArray();
            if (!next.TryCapture(keys, signatures, out var observation) || !next.TryApply(observation))
                return DnssecAnchorRefreshOutcome.Refused;
            token.ThrowIfCancellationRequested();
            lock (gate) { if (closing) return DnssecAnchorRefreshOutcome.Refused; }
            return CommitAndAdopt(next, token);
        }
        finally
        {
            lock (gate)
            {
                active = false;
                if (closing) drained.TrySetResult();
            }
        }
    }

    private DnssecAnchorRefreshOutcome CommitAndAdopt(DnssecTrustAnchorTracker candidate, CancellationToken token)
    {
        try
        {
            var revision = store.Commit(current.Revision, candidate, token);
            if (revision != checked(current.Revision + 1)) throw new InvalidDataException("Anchor store acknowledgement revision changed.");
            var snapshot = new DnssecAnchorRefreshSnapshot(candidate.Origin, revision, candidate.GetTrustAnchors());
            lock (gate)
            {
                tracker = candidate;
                current = snapshot;
            }
            return DnssecAnchorRefreshOutcome.Applied;
        }
        catch
        {
            // Includes cancellation or adoption errors after a possibly durable commit.
            lock (gate) faulted = true;
            throw;
        }
    }
}
