using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed partial class DnssecTrustAnchorTracker
{
    public const int MaximumCheckpointBytes = 1_048_576;

    // Checkpoints contain trusted local state, not a DNS authentication proof.
    // The checksum detects damage; storage authenticity, atomicity and rollback
    // prevention remain the caller's responsibility. Captures are never saved.
    public byte[] CreateCheckpoint()
    {
        lock (gate)
        {
            if (applying)
                throw new InvalidOperationException("Cannot checkpoint during verification.");
            var stamp = ReadClock();
            var ordered = entries.OrderBy(pair => pair.Key, StringComparer.Ordinal).ToArray();
            var indices = ordered.Select((pair, index) => (pair.Key, index))
                .ToDictionary(pair => pair.Key, pair => (byte)pair.index, StringComparer.Ordinal);
            var saved = ordered.Select(pair => new DnssecAnchorCheckpoint.Entry(pair.Value.Key, pair.Value.State,
                pair.Value.State == DnssecAnchorState.AddPending ? Remaining(pair.Value, stamp).Ticks : 0,
                pair.Value.Sponsors.Order(StringComparer.Ordinal).Select(id => new DnssecAnchorCheckpoint.Sponsor(indices[id],
                    pair.Value.EarlyRevocations.Contains(id)
                    || entries[id].RevokedAt is { } revoked && Remaining(pair.Value, revoked) != TimeSpan.Zero)).ToArray())).ToArray();
            return DnssecAnchorCheckpoint.Encode(Origin, stamp.Seconds, saved);
        }
    }

    // Explicit trusted recovery never combines a checkpoint with bootstrap keys.
    // Downtime does not spend hold-down: remaining time restarts on BOTH clocks,
    // using the saved wall high-water mark, and promotion still needs a new proof.
    public static DnssecTrustAnchorTracker RestoreCheckpoint(DnsName expectedOrigin, ReadOnlySpan<byte> trustedCheckpoint,
        IDnssecSignatureVerifier verifier, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(expectedOrigin);
        ArgumentNullException.ThrowIfNull(verifier);
        var saved = DnssecAnchorCheckpoint.Decode(expectedOrigin, trustedCheckpoint);
        var tracker = new DnssecTrustAnchorTracker(expectedOrigin, verifier, time ?? TimeProvider.System);
        var stamp = tracker.ReadClock();
        tracker.latestSeconds = Math.Max(stamp.Seconds, saved.Seconds);
        foreach (var entry in saved.Entries)
        {
            var sponsors = entry.Sponsors.Select(sponsor => DnssecAnchorProof.Identity(saved.Entries[sponsor.Index].Key.GetData())).ToArray();
            tracker.entries.Add(DnssecAnchorProof.Identity(entry.Key.GetData()), new Entry(entry.Key, entry.State)
            {
                Timestamp = stamp.Timestamp,
                Seconds = tracker.latestSeconds,
                HoldDown = TimeSpan.FromTicks(entry.RemainingTicks),
                Sponsors = sponsors,
                EarlyRevocations = entry.Sponsors.Where(sponsor => sponsor.EarlyRevocation)
                    .Select(sponsor => DnssecAnchorProof.Identity(saved.Entries[sponsor.Index].Key.GetData()))
                    .ToHashSet(StringComparer.Ordinal),
            });
        }
        return tracker;
    }

    private DnssecTrustAnchorTracker(DnsName origin, IDnssecSignatureVerifier verifier, TimeProvider time)
    {
        Origin = origin;
        this.verifier = verifier;
        this.time = time;
    }
}
