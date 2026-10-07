using System.Buffers.Binary;
using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Dnssec;

namespace Mk8.Dns.Application.BLL;

public sealed class ZoneResigningApplication
{
    private readonly IZoneResigningStore store;
    private readonly IZoneBundleCodec codec;
    private readonly IDnssecSignatureVerifier verifier;
    private readonly TimeProvider time;
    private readonly string targetNode;
    private readonly Dictionary<Guid, DnssecRenewalScope> scopes;
    private readonly Dictionary<Guid, Generation> verified = [];
    private readonly Lock cacheLock = new();

    public ZoneResigningApplication(IZoneResigningStore store, IZoneBundleCodec codec, IDnssecSignatureVerifier verifier, TimeProvider time, string targetNode, IEnumerable<DnssecRenewalScope> scopes)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentException.ThrowIfNullOrEmpty(targetNode);
        ArgumentNullException.ThrowIfNull(scopes);
        var selected = scopes.Take(65).ToArray();
        if (selected.Length is 0 or > 64 || selected.Any(scope => scope is null)
            || selected.Select(scope => scope.ZoneId).Distinct().Count() != selected.Length
            || selected.Select(scope => scope.Origin).Distinct().Count() != selected.Length)
            throw new ArgumentException("Renewal requires bounded, unique exact signing scopes.", nameof(scopes));
        this.store = store;
        this.codec = codec;
        this.verifier = verifier;
        this.time = time;
        this.targetNode = targetNode;
        this.scopes = selected.ToDictionary(scope => scope.ZoneId);
    }

    public async ValueTask<bool> ResignAsync(Guid zoneId, CancellationToken cancellationToken)
    {
        if (!scopes.TryGetValue(zoneId, out var scope))
            throw new ArgumentException("Zone is outside the configured renewal scope.", nameof(zoneId));
        var transaction = await store.BeginAsync(cancellationToken).ConfigureAwait(false);
        await using var lifetime = transaction.ConfigureAwait(false);
        var ownership = await transaction.ReadOwnershipAsync(cancellationToken).ConfigureAwait(false);
        var owner = ownership.SingleOrDefault(item => item.ZoneId == zoneId);
        if (owner is null)
            return false;
        if (!owner.Origin.Equals(scope.Origin) || owner.TenantId == Guid.Empty)
            throw new InvalidOperationException("Renewal scope conflicts with committed ownership.");
        var current = await transaction.ReadZoneAsync(owner.TenantId, zoneId, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Committed ownership has no current generation.");
        if (current.ZoneId != zoneId || !current.Origin.Equals(scope.Origin))
            throw new InvalidOperationException("Current generation conflicts with the renewal scope.");
        var operation = await transaction.ReadGenerationAsync(owner.TenantId, zoneId, current.Revision, cancellationToken).ConfigureAwait(false);
        RequireGeneration(operation, owner.TenantId, current);
        if (!operation!.Activated || await transaction.HasPendingAsync(zoneId, cancellationToken).ConfigureAwait(false))
            return false;
        var contents = codec.DecodeContents(current);
        if (!contents.IsSigned)
            return false;
        var previous = VerifyRetained(current, contents);
        var now = unchecked((uint)time.GetUtcNow().ToUnixTimeSeconds());
        if (!IsDue(previous.Window, now, scope.RenewBeforeSeconds))
            return false;
        cancellationToken.ThrowIfCancellationRequested();
        var source = WithSerial(contents.Source, SoaSerial.Next(current.Serial));
        var next = codec.Compile(zoneId, checked(current.Revision + 1), source);
        var signed = codec.DecodeContents(next);
        SigningContinuity.Require(contents, signed);
        var proof = SignedZoneAdmission.Verify(signed, unchecked((uint)time.GetUtcNow().ToUnixTimeSeconds()), verifier);
        RequireReplacement(current, next, source, proof, previous, scope);
        cancellationToken.ThrowIfCancellationRequested();
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData([.. "M8N1"u8, .. current.ZoneId.ToByteArray(), .. Convert.FromHexString(current.ContentHash)]));
        var renewal = new ZoneOperation(owner.TenantId, Guid.NewGuid(), fingerprint, "mk8.dns:signature-renewal", targetNode, next, Activated: false);
        await transaction.AppendAsync(renewal, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        lock (cacheLock)
            verified[zoneId] = new Generation(next.Revision, next.ContentHash, proof);
        return true;
    }

    private void RequireGeneration(ZoneOperation? operation, Guid tenantId, ZoneSnapshot current)
    {
        if (operation is null || operation.TenantId != tenantId || operation.Snapshot.ZoneId != current.ZoneId
            || !operation.Snapshot.Origin.Equals(current.Origin) || operation.Snapshot.Revision != current.Revision
            || operation.Snapshot.Serial != current.Serial || !string.Equals(operation.Snapshot.ContentHash, current.ContentHash, StringComparison.Ordinal)
            || !string.Equals(operation.TargetNode, targetNode, StringComparison.Ordinal))
            throw new InvalidOperationException("Current generation has no matching publication evidence.");
    }

    private VerifiedSignedZone VerifyRetained(ZoneSnapshot snapshot, ZoneContents contents)
    {
        lock (cacheLock)
            if (verified.TryGetValue(snapshot.ZoneId, out var cached) && cached.Revision == snapshot.Revision
                && string.Equals(cached.Hash, snapshot.ContentHash, StringComparison.Ordinal))
                return cached.Proof;
        var proof = SignedZoneAdmission.VerifyRetained(contents, verifier);
        lock (cacheLock)
            verified[snapshot.ZoneId] = new Generation(snapshot.Revision, snapshot.ContentHash, proof);
        return proof;
    }

    private void RequireReplacement(ZoneSnapshot current, ZoneSnapshot next, AuthoritativeZone source, VerifiedSignedZone proof, VerifiedSignedZone previous, DnssecRenewalScope scope)
    {
        if (next.ZoneId != current.ZoneId || !next.Origin.Equals(current.Origin) || next.Revision != current.Revision + 1 || next.Serial != source.Soa.GetSoaSerial()
            || !string.Equals(codec.CompileIntent(next.ZoneId, 1, source).ContentHash, codec.CompileIntent(next.ZoneId, 1, proof.Contents.Source).ContentHash, StringComparison.Ordinal)
            || unchecked(proof.Window.Expiration - proof.Window.Inception) != scope.LifetimeSeconds + 300
            || !SoaSerial.IsNewer(proof.Window.Expiration, previous.Window.Expiration))
            throw new InvalidOperationException("Renewal did not preserve intent and advance the signed generation.");
    }

    private static bool IsDue(DnssecSignatureWindow window, uint now, uint margin)
    {
        var issued = unchecked(window.Inception + 300);
        var age = unchecked(now - issued);
        if (age is < 60 or >= 0x80000000)
            return false;
        return window.Contains(now) ? unchecked(window.Expiration - now) <= margin : SoaSerial.IsNewer(now, window.Expiration);
    }

    private static AuthoritativeZone WithSerial(AuthoritativeZone zone, uint serial)
    {
        var data = zone.Soa.GetData();
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(data.Length - 20), serial);
        var soa = new DnsRecord(zone.Soa.GetOwnerWire(), 6, zone.Soa.Ttl, data);
        return new AuthoritativeZone(zone.Origin, zone.GetAllRecords().Select(record => record.Type == 6 ? soa : record));
    }

    private sealed record Generation(long Revision, string Hash, VerifiedSignedZone Proof);
}
