using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Application.DAL;

public sealed partial class FileAnchorCheckpointStore
{
    DnssecStoredAnchorCheckpoint IDnssecAnchorCheckpointStore.ReadCommitted()
    {
        lock (sync)
        {
            RequireHealthy();
            var state = VerifyCurrentState();
            return new DnssecStoredAnchorCheckpoint(origin, state.Revision, state.Checkpoint);
        }
    }

    long IDnssecAnchorCheckpointStore.Commit(long expectedRevision, DnssecTrustAnchorTracker candidate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        cancellationToken.ThrowIfCancellationRequested();
        lock (sync)
        {
            RequireHealthy(); cancellationToken.ThrowIfCancellationRequested();
            if (!candidate.Origin.Equals(origin)) throw new ArgumentException("Anchor checkpoint origin changed.", nameof(candidate));
            if (expectedRevision != revision) throw new InvalidOperationException("Anchor revision changed.");
            if (RetentionCapacityExhausted()) throw new IOException("Anchor retention capacity requires explicit maintenance.");
            VerifyWritableState();
            var checkpoint = candidate.CreateCheckpoint();
            cancellationToken.ThrowIfCancellationRequested();
            Commit(checkpoint);
            // Publish the replacement tracker only after the complete durable acknowledgement.
            tracker = candidate;
            return revision;
        }
    }
}
