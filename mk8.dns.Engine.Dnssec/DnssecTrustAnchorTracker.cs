using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

// Supplied-observation, in-memory foundation. The caller owns authenticated
// transport selection, fresh acquisition, clocks, refresh and durable recovery.
public sealed partial class DnssecTrustAnchorTracker
{
    public const int MaximumTrackedKeys = 64;
    private static readonly TimeSpan MinimumAddHoldDown = TimeSpan.FromDays(30);
    private readonly Lock gate = new();
    private readonly IDnssecSignatureVerifier verifier;
    private readonly TimeProvider time;
    private readonly Dictionary<string, Entry> entries = new(StringComparer.Ordinal);
    private long latestTimestamp;
    private long latestSeconds;
    private long nextSequence;
    private long consumedSequence;
    private DnssecAnchorObservation? pendingObservation;
    private bool clockStarted;
    private bool applying;

    public DnssecTrustAnchorTracker(DnsName origin, IReadOnlyList<DnsRecord> initialKeys,
        IDnssecSignatureVerifier verifier, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(initialKeys);
        ArgumentNullException.ThrowIfNull(verifier);
        if (!DnssecValidationInput.TryRrset(initialKeys, origin, 48, MaximumTrackedKeys, out var records))
            throw new ArgumentException("An exact non-wildcard DNSKEY trust point is required.", nameof(initialKeys));
        foreach (var record in records)
        {
            if (!DnssecAnchorProof.TryKey(record, revoked: false, out var identity))
                throw new ArgumentException("Initial anchors must be usable non-revoked SEP zone keys.", nameof(initialKeys));
            entries.Add(DnssecAnchorProof.Identity(identity), new Entry(record.WithTtl(0), DnssecAnchorState.Valid));
        }
        Origin = origin;
        this.verifier = verifier;
        this.time = time ?? TimeProvider.System;
    }

    public DnsName Origin { get; }

    public bool TryCapture(IReadOnlyList<DnsRecord> dnskeys, IReadOnlyList<DnsRecord> signatures,
        [NotNullWhen(true)] out DnssecAnchorObservation? observation)
    {
        ArgumentNullException.ThrowIfNull(dnskeys);
        ArgumentNullException.ThrowIfNull(signatures);
        observation = null;
        lock (gate)
        {
            if (applying) return false;
            // At most one owned capture is retained. A newer capture retires the
            // old one; caller tokens cannot accumulate DNSKEY material here.
            pendingObservation?.Release();
            pendingObservation = null;
            var stamp = ReadClock();
            if (!DnssecValidationInput.TryRrset(dnskeys, Origin, 48, MaximumTrackedKeys, out var records)
                || !DnssecValidationInput.TrySignatures(signatures, out var sigs))
            {
                return false;
            }

            var identities = new HashSet<string>(StringComparer.Ordinal);
            foreach (var record in records)
            {
                if ((DnssecAnchorProof.TryKey(record, revoked: false, out var identity)
                    || DnssecAnchorProof.TryKey(record, revoked: true, out identity))
                    && !identities.Add(DnssecAnchorProof.Identity(identity)))
                {
                    return false;
                }
            }

            observation = new DnssecAnchorObservation(this, checked(++nextSequence), stamp.Timestamp, stamp.Seconds, records, sigs);
            pendingObservation = observation;
            return true;
        }
    }

    public bool TryApply(DnssecAnchorObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        lock (gate)
        {
            if (!ReferenceEquals(observation.Creator, this) || !ReferenceEquals(pendingObservation, observation)
                || observation.Sequence <= consumedSequence)
            {
                return false;
            }

            consumedSequence = observation.Sequence;
            pendingObservation = null;
            applying = true;
            try { return Apply(observation); }
            finally { observation.Release(); applying = false; }
        }
    }

    private bool Apply(DnssecAnchorObservation observation)
    {
        var attempts = 0;
        var sponsors = new Dictionary<string, DnssecAnchorProof.Verified>(StringComparer.Ordinal);
        var revocations = new Dictionary<string, DnssecAnchorProof.Verified>(StringComparer.Ordinal);
        var candidates = new Dictionary<string, DnsRecord>(StringComparer.Ordinal);
        foreach (var record in observation.Records)
        {
            if (DnssecAnchorProof.TryKey(record, revoked: false, out var identity))
            {
                candidates.TryAdd(DnssecAnchorProof.Identity(identity), record);
            }
            else if (DnssecAnchorProof.TryKey(record, revoked: true, out identity))
            {
                var id = DnssecAnchorProof.Identity(identity);
                if (entries.TryGetValue(id, out var entry) && entry.State != DnssecAnchorState.Revoked)
                    Verify(observation, record, id, revocations, ref attempts);
            }
        }
        foreach (var pair in entries)
        {
            if (pair.Value.State is DnssecAnchorState.Valid or DnssecAnchorState.Missing)
                Verify(observation, pair.Value.Key, pair.Key, sponsors, ref attempts);
        }

        if (attempts > DnssecChainValidator.MaximumVerificationAttempts)
            return false;
        var final = ReadClock();
        // Revocation is independent of another anchor's authentication. Only
        // live self-proofs mutate trust; failed provider work mutates nothing.
        foreach (var pair in revocations)
        {
            if (Fresh(pair.Value, observation, final))
            {
                entries[pair.Key].State = DnssecAnchorState.Revoked;
                entries[pair.Key].RevokedAt = new Stamp(observation.Timestamp, observation.Seconds);
            }
        }

        foreach (var id in sponsors.Keys.ToArray())
        {
            if (entries[id].State == DnssecAnchorState.Revoked || !Fresh(sponsors[id], observation, final))
                sponsors.Remove(id);
        }

        ResetUnsupportedPending();
        if (sponsors.Count == 0)
        {
            var applied = revocations.Any(pair => entries[pair.Key].State == DnssecAnchorState.Revoked);
            if (applied) RecordTiming(observation, sponsors, revocations, final);
            return applied;
        }
        Update(candidates, sponsors, observation);
        RecordTiming(observation, sponsors, revocations, final);
        return true;
    }
    public IReadOnlyList<DnssecAnchorStatus> GetStatus()
    {
        lock (gate)
        {
            var stamp = ReadClock();
            return Array.AsReadOnly(entries.Values.Select(entry => new DnssecAnchorStatus(entry.Key, entry.State,
                entry.State == DnssecAnchorState.AddPending ? Remaining(entry, stamp) : TimeSpan.Zero)).ToArray());
        }
    }

    public IReadOnlyList<DnssecTrustAnchor> GetTrustAnchors()
    {
        lock (gate)
        {
            return Array.AsReadOnly(entries.Values.Where(entry => entry.State is DnssecAnchorState.Valid or DnssecAnchorState.Missing)
                .Select(entry => new DnssecTrustAnchor(entry.Key)).ToArray());
        }
    }

    private void Verify(DnssecAnchorObservation observation, DnsRecord key, string identity,
        Dictionary<string, DnssecAnchorProof.Verified> proofs, ref int attempts)
    {
        foreach (var signature in observation.Signatures)
        {
            if (DnssecAnchorProof.TryVerify(observation.Records, signature, key, unchecked((uint)observation.Seconds),
                verifier, ref attempts, out var proof))
            {
                proofs.Add(identity, proof!);
                return;
            }
        }
    }

    private void Update(Dictionary<string, DnsRecord> candidates, Dictionary<string, DnssecAnchorProof.Verified> sponsors,
        DnssecAnchorObservation observation)
    {
        foreach (var pair in entries.ToArray())
        {
            var entry = pair.Value;
            if (entry.State == DnssecAnchorState.Revoked)
                continue;
            if (!candidates.ContainsKey(pair.Key))
            {
                if (entry.State == DnssecAnchorState.AddPending) entries.Remove(pair.Key);
                else entry.State = DnssecAnchorState.Missing;
            }
            else if (entry.State == DnssecAnchorState.Missing)
            {
                entry.State = DnssecAnchorState.Valid;
            }
            else if (entry.State == DnssecAnchorState.AddPending && Remaining(entry, new Stamp(observation.Timestamp, observation.Seconds)) == TimeSpan.Zero)
            {
                entry.State = DnssecAnchorState.Valid;
            }
        }
        var originalTtl = sponsors.Values.Max(proof => proof.OriginalTtl);
        foreach (var pair in candidates)
        {
            if (entries.ContainsKey(pair.Key) || entries.Count == MaximumTrackedKeys)
                continue;
            entries.Add(pair.Key, new Entry(pair.Value.WithTtl(0), DnssecAnchorState.AddPending)
            {
                Timestamp = observation.Timestamp,
                Seconds = observation.Seconds,
                HoldDown = TimeSpan.FromSeconds(Math.Max(MinimumAddHoldDown.TotalSeconds, originalTtl)),
                Sponsors = [.. sponsors.Keys],
            });
        }
    }

    private void ResetUnsupportedPending()
    {
        foreach (var pair in entries.ToArray())
        {
            if (pair.Value.State == DnssecAnchorState.AddPending && pair.Value.Sponsors.All(id =>
                    pair.Value.EarlyRevocations.Contains(id)
                    || (entries[id].RevokedAt is { } revoked && Remaining(pair.Value, revoked) != TimeSpan.Zero)))
            {
                entries.Remove(pair.Key);
            }
        }
    }

    private bool Fresh(DnssecAnchorProof.Verified proof, DnssecAnchorObservation observation, Stamp final)
        => proof.Window.Contains(unchecked((uint)final.Seconds))
            && time.GetElapsedTime(observation.Timestamp, final.Timestamp).TotalSeconds < proof.ReceivedTtl
            && final.Seconds - observation.Seconds < proof.ReceivedTtl;

    private TimeSpan Remaining(Entry entry, Stamp stamp)
    {
        var elapsed = Math.Min(Math.Max(0, time.GetElapsedTime(entry.Timestamp, stamp.Timestamp).TotalSeconds),
            Math.Max(0, stamp.Seconds - entry.Seconds));
        return TimeSpan.FromSeconds(Math.Max(0, entry.HoldDown.TotalSeconds - elapsed));
    }

    private Stamp ReadClock()
    {
        var seconds = time.GetUtcNow().ToUnixTimeSeconds();
        var timestamp = time.GetTimestamp();
        if (!clockStarted || timestamp > latestTimestamp) latestTimestamp = timestamp;
        if (!clockStarted || seconds > latestSeconds) latestSeconds = seconds;
        clockStarted = true;
        return new Stamp(latestTimestamp, latestSeconds);
    }

    private sealed class Entry(DnsRecord key, DnssecAnchorState state)
    {
        internal DnsRecord Key { get; } = key;
        internal DnssecAnchorState State { get; set; } = state;
        internal long Timestamp { get; init; }
        internal long Seconds { get; init; }
        internal TimeSpan HoldDown { get; init; }
        internal string[] Sponsors { get; init; } = [];
        internal HashSet<string> EarlyRevocations { get; init; } = new(StringComparer.Ordinal);
        internal Stamp? RevokedAt { get; set; }
    }

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct Stamp(long Timestamp, long Seconds);
}
