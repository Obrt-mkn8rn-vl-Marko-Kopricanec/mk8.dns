using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Engine.Dnssec;

public sealed class DnssecChainValidator
{
    public const int MaximumKeys = 64;
    public const int MaximumSignatures = 16;
    public const int MaximumRrsetRecords = 512;
    public const int MaximumDepth = 16;
    public const int MaximumVerificationAttempts = 128;
    private readonly Lock clockGate = new();
    private readonly IDnssecSignatureVerifier verifier;
    private readonly TimeProvider time;
    private bool clockStarted;
    private long latestTimestamp;

    public DnssecChainValidator(IDnssecSignatureVerifier verifier, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        this.verifier = verifier;
        this.time = time ?? TimeProvider.System;
    }

    public bool TryAuthenticateAnchor(DnssecTrustAnchor anchor, IReadOnlyList<DnsRecord> dnskeys,
        IReadOnlyList<DnsRecord> signatures, [NotNullWhen(true)] out AuthenticatedDnskeySet? authenticatedKeys)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        ArgumentNullException.ThrowIfNull(dnskeys);
        ArgumentNullException.ThrowIfNull(signatures);
        authenticatedKeys = null;
        var stamp = ReadClock();
        if (!DnssecValidationInput.TryRrset(dnskeys, anchor.Origin, 48, MaximumKeys, out var records)
            || !DnssecValidationInput.TrySignatures(signatures, out var sigs))
            return false;
        var eligible = records.Where(DnssecValidationInput.IsUsableKey).Where(anchor.Matches).ToArray();
        if (!TryVerify(records, sigs, eligible, stamp, new Budget(), out var proof))
            return false;
        return Admit(anchor.Origin, records, stamp, proof.Ttl, [proof.Window], 1, out authenticatedKeys);
    }

    // The caller supplies the actual selected parent/child cut. This verifies its
    // cryptographic path, not referral selection, DS absence or DNS security status.
    public bool TryAuthenticateChild(AuthenticatedDnskeySet parent, DnsName child, IReadOnlyList<DnsRecord> ds,
        IReadOnlyList<DnsRecord> dsSignatures, IReadOnlyList<DnsRecord> dnskeys, IReadOnlyList<DnsRecord> keySignatures,
        [NotNullWhen(true)] out AuthenticatedDnskeySet? authenticatedKeys)
    {
        ArgumentNullException.ThrowIfNull(parent);
        ArgumentNullException.ThrowIfNull(child);
        ArgumentNullException.ThrowIfNull(ds);
        ArgumentNullException.ThrowIfNull(dsSignatures);
        ArgumentNullException.ThrowIfNull(dnskeys);
        ArgumentNullException.ThrowIfNull(keySignatures);
        authenticatedKeys = null;
        var stamp = ReadClock();
        var parentTtl = Remaining(parent, stamp);
        if (parentTtl == 0 || parent.Depth >= MaximumDepth || child.Equals(parent.Origin) || !child.IsSubdomainOf(parent.Origin)
            || !DnssecValidationInput.TryRrset(ds, child, 43, MaximumKeys, out var delegations)
            || !DnssecValidationInput.TrySignatures(dsSignatures, out var delegationSigs)
            || !DnssecValidationInput.TryRrset(dnskeys, child, 48, MaximumKeys, out var records)
            || !DnssecValidationInput.TrySignatures(keySignatures, out var keySigs))
            return false;
        var budget = new Budget();
        if (!TryVerify(delegations, delegationSigs, parent.UsableKeys, stamp, budget, out var delegationProof))
            return false;
        var eligible = records.Where(DnssecValidationInput.IsUsableKey)
            .Where(key => delegations.Any(delegation => DnssecValidationInput.MatchesDs(delegation, key))).ToArray();
        if (!TryVerify(records, keySigs, eligible, stamp, budget, out var keyProof))
            return false;
        var ttl = Math.Min(parentTtl, Math.Min(delegationProof.Ttl, keyProof.Ttl));
        return Admit(child, records, stamp, ttl, [.. parent.Windows, delegationProof.Window, keyProof.Window], parent.Depth + 1, out authenticatedKeys);
    }

    // Exact-owner RRset integrity only. Wildcard, denial, alias resolution and
    // actual zone-cut provenance must be established separately by the resolver.
    public bool TryAuthenticateRrset(AuthenticatedDnskeySet keys, DnsQuestion expected, IReadOnlyList<DnsRecord> records,
        IReadOnlyList<DnsRecord> signatures, out uint authenticatedTtl)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(signatures);
        authenticatedTtl = 0;
        var stamp = ReadClock();
        if (Remaining(keys, stamp) == 0 || expected.Name is null || expected.Class != 1 || !expected.Name.IsSubdomainOf(keys.Origin)
            || expected.Type == 48 && !expected.Name.Equals(keys.Origin) || expected.Type == 43 && expected.Name.Equals(keys.Origin)
            || !DnssecValidationInput.TryRrset(records, expected.Name, expected.Type, MaximumRrsetRecords, out var items)
            || !DnssecValidationInput.TrySignatures(signatures, out var sigs)
            || !TryVerify(items, sigs, keys.UsableKeys, stamp, new Budget(), out var proof))
            return false;
        var final = ReadClock();
        var keyTtl = Remaining(keys, final);
        if (keyTtl == 0 || !proof.Window.Contains(final.Now))
            return false;
        authenticatedTtl = Math.Min(keyTtl, Math.Min(Age(proof.Ttl, stamp.Received, final.Received), unchecked(proof.Window.Expiration - final.Now)));
        return true;
    }

    public uint GetRemainingTtl(AuthenticatedDnskeySet keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        return Remaining(keys, ReadClock());
    }

    private bool TryVerify(DnsRecord[] records, DnsRecord[] signatures, DnsRecord[] eligible,
        Stamp stamp, Budget budget, [NotNullWhen(true)] out Proof? proof)
    {
        proof = null;
        foreach (var signature in signatures)
        {
            RrsigData data;
            try { data = RrsigData.Decode(signature); }
            catch (Exception error) when (error is FormatException or ArgumentException) { continue; }
            if (!signature.Owner.Equals(records[0].Owner) || data.Type != records[0].Type || data.Labels != records[0].Owner.LabelCount)
                continue;
            foreach (var key in eligible)
            {
                if (!data.Signer.Equals(key.Owner) || data.KeyTag != DnssecKeys.KeyTag(key))
                    continue;
                if (!budget.Take())
                    return false;
                if (DnssecRrsetVerifier.TryVerify(records, signature, key, stamp.Now, verifier, out var ttl))
                {
                    proof = new Proof(data.Window, ttl);
                    return true;
                }
            }
        }
        return false;
    }

    private bool Admit(DnsName origin, DnsRecord[] records, Stamp stamp, uint ttl, DnssecSignatureWindow[] windows,
        int depth, [NotNullWhen(true)] out AuthenticatedDnskeySet? keys)
    {
        keys = null;
        var candidate = new AuthenticatedDnskeySet(this, origin, records, stamp.Received, ttl, windows, depth);
        if (Remaining(candidate, ReadClock()) == 0)
            return false;
        keys = candidate;
        return true;
    }

    private uint Remaining(AuthenticatedDnskeySet keys, Stamp stamp)
    {
        if (!ReferenceEquals(keys.Creator, this))
            return 0;
        var ttl = Age(keys.Ttl, keys.Received, stamp.Received);
        foreach (var window in keys.Windows)
        {
            if (!window.Contains(stamp.Now))
                return 0;
            ttl = Math.Min(ttl, unchecked(window.Expiration - stamp.Now));
        }
        return ttl;
    }

    private uint Age(uint ttl, long received, long now)
    {
        var elapsed = Math.Ceiling(Math.Max(0, time.GetElapsedTime(received, now).TotalSeconds));
        return elapsed >= ttl ? 0 : ttl - (uint)elapsed;
    }

    private Stamp ReadClock()
    {
        var now = unchecked((uint)time.GetUtcNow().ToUnixTimeSeconds());
        var timestamp = time.GetTimestamp();
        lock (clockGate)
        {
            if (!clockStarted || timestamp > latestTimestamp) latestTimestamp = timestamp;
            clockStarted = true;
            return new Stamp(latestTimestamp, now);
        }
    }

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct Stamp(long Received, uint Now);
    private sealed record Proof(DnssecSignatureWindow Window, uint Ttl);
    private sealed class Budget
    {
        private int remaining = MaximumVerificationAttempts;
        internal bool Take() => --remaining >= 0;
    }
}
