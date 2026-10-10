using Microsoft.Win32.SafeHandles;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Application.DAL;

public sealed partial class FileAnchorCheckpointStore
{
    private readonly bool retentionEnabled;
    private long firstRetainedRevision = 1;
    private long trustedFloor = 1;
    private byte[] firstPreviousDigest = new byte[32];

    public static FileAnchorCheckpointStore CreateWithRetention(string directory, Guid storageId,
        DnssecTrustAnchorTracker initial, ReadOnlySpan<byte> authenticationKey)
        => CreateRetentionCore(directory, storageId, initial, authenticationKey, hook: null);

    internal static FileAnchorCheckpointStore CreateRetentionCore(string directory, Guid storageId,
        DnssecTrustAnchorTracker initial, ReadOnlySpan<byte> key, Action<AnchorStoreWriteStage>? hook,
        Func<SafeFileHandle, int, int>? nativeLock = null)
    {
        ArgumentNullException.ThrowIfNull(initial);
        var store = new FileAnchorCheckpointStore(directory, storageId, initial.Origin, key, create: true,
            hook, nativeLock, retention: true);
        try { store.Initialize(initial); return store; }
        catch { store.Dispose(); throw; }
    }

    public static FileAnchorCheckpointStore OpenWithRetention(string directory, Guid storageId,
        DnsName expectedOrigin, ReadOnlySpan<byte> authenticationKey, long minimumRevision,
        IDnssecSignatureVerifier verifier, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentOutOfRangeException.ThrowIfLessThan(minimumRevision, 1);
        var store = new FileAnchorCheckpointStore(directory, storageId, expectedOrigin, authenticationKey,
            create: false, retention: true);
        try
        {
            store.trustedFloor = minimumRevision;
            var state = store.ReadState(allowInitial: false);
            store.tracker = DnssecTrustAnchorTracker.RestoreCheckpoint(expectedOrigin, state.Checkpoint, verifier, time);
            store.revision = state.Revision; store.digest = state.Digest;
            store.firstRetainedRevision = state.First;
            store.firstPreviousDigest = state.Previous ?? throw new InvalidDataException("Retained anchor boundary is missing.");
            return store;
        }
        catch { store.Dispose(); throw; }
    }

    public long FirstRetainedRevision { get { lock (sync) { RequireHealthy(); return firstRetainedRevision; } } }

    // The caller must independently persist/acknowledge this floor BEFORE calling.
    // Returns the first retained revision; the logical revision/checkpoint do not change.
    public long Retain(long expectedRevision, long trustedMinimumRevision, int generationsToKeep,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentOutOfRangeException.ThrowIfLessThan(generationsToKeep, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(generationsToKeep, MaximumGenerations);
        lock (sync)
        {
            RequireHealthy(); cancellationToken.ThrowIfCancellationRequested();
            if (!retentionEnabled) throw new InvalidOperationException("This store was not created for explicit retention.");
            if (expectedRevision != revision) throw new InvalidOperationException("Anchor revision changed.");
            var first = Math.Max(firstRetainedRevision, revision - generationsToKeep + 1);
            if (trustedMinimumRevision < Math.Max(trustedFloor, first) || trustedMinimumRevision > revision)
                throw new ArgumentOutOfRangeException(nameof(trustedMinimumRevision), "An independently acknowledged floor must cover the new boundary.");
            var state = VerifyCurrentState();
            if (first == firstRetainedRevision && state.Retired == 0)
            {
                trustedFloor = trustedMinimumRevision; return first;
            }
            return RetainVerified(first, trustedMinimumRevision, cancellationToken);
        }
    }

    private long RetainVerified(long first, long minimum, CancellationToken token)
    {
        try
        {
            var generation = AnchorRetentionEnvelope.DecodeGeneration(ReadBounded(GenerationPath(first)), identity, origin, authenticationKey);
            if (generation.Revision != first) throw new InvalidDataException("Retention boundary identity changed.");
            token.ThrowIfCancellationRequested();
            RetainCore(first, generation.Previous, token);
            trustedFloor = minimum;
            return firstRetainedRevision;
        }
        catch (OperationCanceledException error) when (token.IsCancellationRequested && error.CancellationToken == token)
        {
            // RetainCore faults ownership if a callback cancels after effects began.
            throw;
        }
        catch { faulted = true; throw; }
    }

    private bool RetentionCapacityExhausted()
        => retentionEnabled ? revision == long.MaxValue || revision - firstRetainedRevision + 1 >= MaximumGenerations
            : revision >= MaximumGenerations;

    private void VerifyWritableState()
    {
        var state = VerifyCurrentState();
        if (retentionEnabled && state.Retired != 0)
            throw new IOException("Acknowledged retention requires explicit retired-prefix cleanup before another commit.");
    }
}
