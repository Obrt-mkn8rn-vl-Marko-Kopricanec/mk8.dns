using System.Security.Cryptography;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Application.DAL;

public sealed partial class FileAnchorCheckpointStore
{
    private void InitializeRetention(DnssecTrustAnchorTracker initial)
    {
        var entries = InspectRetentionEntries();
        if (lease.Length != 0 || entries.Generations.Count != 0 || entries.Pointer)
            throw new InvalidDataException("Previously initialized anchor storage cannot be bootstrapped.");
        tracker = initial;
        var checkpoint = initial.CreateCheckpoint();
        var marker = AnchorRetentionEnvelope.EncodeMarker(identity, origin, authenticationKey);
        lease.Write(marker); lease.Flush(flushToDisk: true); NativeDirectorySync.Flush(root);
        CommitRetained(checkpoint);
    }

    private void CommitRetained(byte[] checkpoint)
    {
        var next = checked(revision + 1);
        var generation = AnchorRetentionEnvelope.EncodeGeneration(identity, origin, next, digest, checkpoint, authenticationKey);
        var nextDigest = SHA256.HashData(generation);
        try
        {
            Publish(generation, GenerationPath(next), overwrite: false, AnchorStoreWriteStage.GenerationFile, AnchorStoreWriteStage.GenerationDirectory);
            var value = new AnchorRetentionEnvelope.Pointer(next, firstRetainedRevision, firstPreviousDigest, nextDigest);
            var pointer = AnchorRetentionEnvelope.EncodePointer(identity, origin, value, authenticationKey);
            Publish(pointer, Path.Combine(root, "active.bin"), overwrite: true, AnchorStoreWriteStage.PointerFile, AnchorStoreWriteStage.PointerDirectory);
            revision = next; digest = nextDigest;
        }
        catch { faulted = true; throw; }
    }

    private void RetainCore(long first, byte[] previous, CancellationToken token)
    {
        var prefix = InspectRetentionEntries().Generations.Where(number => number < first).ToArray();
        foreach (var number in prefix)
        {
            var generation = AnchorRetentionEnvelope.DecodeGeneration(ReadBounded(GenerationPath(number)), identity, origin, authenticationKey);
            if (generation.Revision != number) throw new InvalidDataException("Retired anchor identity changed.");
        }
        token.ThrowIfCancellationRequested();
        var value = new AnchorRetentionEnvelope.Pointer(revision, first, previous, digest);
        var pointer = AnchorRetentionEnvelope.EncodePointer(identity, origin, value, authenticationKey);
        try
        {
            // The authenticated boundary must be acknowledged before any old name is removed.
            Publish(pointer, Path.Combine(root, "active.bin"), overwrite: true,
                AnchorStoreWriteStage.RetentionFile, AnchorStoreWriteStage.RetentionDirectory);
            foreach (var number in prefix)
            {
                File.Delete(GenerationPath(number));
                afterDurableWrite?.Invoke(AnchorStoreWriteStage.RetiredGenerationDeleted);
            }
            NativeDirectorySync.Flush(root);
            afterDurableWrite?.Invoke(AnchorStoreWriteStage.RetiredDirectory);
            firstRetainedRevision = first; firstPreviousDigest = previous;
        }
        catch { faulted = true; throw; }
    }
}
