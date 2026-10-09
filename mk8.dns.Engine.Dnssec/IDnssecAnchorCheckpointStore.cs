namespace Mk8.Dns.Engine.Dnssec;

// A trusted, exclusive local-state port. Commit must acknowledge the complete
// next checkpoint or throw; an exception can leave an ambiguous durable state.
// The caller must not mix another logical writer with a refresh session.
public interface IDnssecAnchorCheckpointStore
{
    DnssecStoredAnchorCheckpoint ReadCommitted();
    long Commit(long expectedRevision, DnssecTrustAnchorTracker candidate, CancellationToken cancellationToken);
}
