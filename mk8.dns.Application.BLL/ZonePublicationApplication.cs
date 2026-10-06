using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;
using Mk8.Dns.Engine.Authoritative;

namespace Mk8.Dns.Application.BLL;

public sealed class ZonePublicationApplication : IZonePublication, IAsyncDisposable
{
    private readonly IZoneSnapshotStore snapshots;
    private readonly IPublicationJournal journal;
    private readonly IPublicationAuthenticator authenticator;
    private readonly IZoneBundleCodec codec;
    private readonly AuthoritativeApplication authority;
    private readonly string node;
    private Dictionary<Guid, AuthoritativeZone> zones = [];
    private readonly Dictionary<Guid, ZoneSnapshot> generations = [];
    private readonly Lock sync = new();
    private Task tail = Task.CompletedTask;
    private bool closed;
    private bool reconciliationRequired;
    private int queued;

    private ZonePublicationApplication(IZoneSnapshotStore snapshots, IPublicationJournal journal, IPublicationAuthenticator authenticator, IZoneBundleCodec codec, AuthoritativeApplication authority, string node)
    {
        this.snapshots = snapshots;
        this.journal = journal;
        this.authenticator = authenticator;
        this.codec = codec;
        this.authority = authority;
        this.node = node;
    }

    public static async ValueTask<ZonePublicationApplication> OpenAsync(IZoneSnapshotStore snapshots, IPublicationJournal journal, IPublicationAuthenticator authenticator, IZoneBundleCodec codec, AuthoritativeApplication authority, string node, IEnumerable<Guid> zoneIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(authenticator);
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentException.ThrowIfNullOrEmpty(node);
        ArgumentNullException.ThrowIfNull(zoneIds);
        var result = new ZonePublicationApplication(snapshots, journal, authenticator, codec, authority, node);
        var ids = zoneIds.Take(65).ToArray();
        if (ids.Length is 0 or > 64 || ids.Distinct().Count() != ids.Length || ids.Contains(Guid.Empty))
            throw new ArgumentException("Distinct configured publication zones are required.", nameof(zoneIds));
        authority.Suspend();
        await result.LoadAsync(ids, cancellationToken).ConfigureAwait(false);
        authority.ReplaceCatalog(new AuthoritativeCatalog(result.zones.Values));
        return result;
    }

    private async ValueTask LoadAsync(Guid[] ids, CancellationToken cancellationToken)
    {
        var active = await snapshots.CountActiveAsync(cancellationToken).ConfigureAwait(false);
        foreach (var id in ids)
        {
            var snapshot = await snapshots.ReadActiveAsync(id, cancellationToken).ConfigureAwait(false);
            if (snapshot is null)
                continue;
            var body = authenticator.CreateBody(snapshot);
            var publicationId = Identity(body);
            var proof = await journal.ReadAsync(publicationId, cancellationToken).ConfigureAwait(false);
            var verified = authenticator.Verify(proof.Body.Span, proof.Signature.Span);
            if (!Same(verified, snapshot))
                throw new InvalidDataException("Active generation differs from its publisher proof.");
            var activation = await journal.ReadActivationSignatureAsync(publicationId, cancellationToken).ConfigureAwait(false);
            authenticator.VerifyActivation(publicationId, activation);
            zones.Add(id, codec.Decode(verified));
            generations.Add(id, verified);
        }
        if (active != zones.Count)
            throw new InvalidDataException("Active storage contains a zone outside the configured publisher scope.");
        foreach (var id in await journal.ReadActivatedIdsAsync(cancellationToken).ConfigureAwait(false))
        {
            var proof = await journal.ReadAsync(id, cancellationToken).ConfigureAwait(false);
            var acknowledged = authenticator.Verify(proof.Body.Span, proof.Signature.Span);
            var signature = await journal.ReadActivationSignatureAsync(id, cancellationToken).ConfigureAwait(false);
            authenticator.VerifyActivation(id, signature);
            if (!generations.TryGetValue(acknowledged.ZoneId, out var current) || current.Revision < acknowledged.Revision || current.Revision == acknowledged.Revision && !Same(current, acknowledged))
                throw new InvalidDataException("Active storage is missing an acknowledged publisher generation; verified reconciliation is required.");
        }
    }

    public ValueTask<PublicationReply> ExecuteAsync(PublicationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Body.Length > ZoneSnapshot.MaximumPayloadBytes + 512 || request.Signature.Length != 64)
            throw new ArgumentException("Invalid publication request bounds.", nameof(request));
        // Clone at admission: a caller cannot mutate a queued authenticated request.
        var copy = request with { Body = request.Body.ToArray(), Signature = request.Signature.ToArray() };
        Task predecessor;
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(closed, this);
            if (queued >= 8)
                throw new InvalidOperationException("Publication admission capacity is exhausted.");
            queued++;
            predecessor = tail;
            tail = completion.Task;
        }
        return RunAsync(predecessor, completion, copy, cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        lock (sync)
        {
            closed = true;
            return new ValueTask(tail);
        }
    }

    private async ValueTask<PublicationReply> RunAsync(Task predecessor, TaskCompletionSource completion, PublicationRequest request, CancellationToken cancellationToken)
    {
        try
        {
            await predecessor.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
                ObjectDisposedException.ThrowIf(closed, this);
            if (reconciliationRequired)
                throw new InvalidOperationException("Publication requires verified restart reconciliation after a storage failure.");
            if (string.Equals(request.Action, "prepare", StringComparison.Ordinal))
                return await PrepareAsync(request, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(request.Action, "activate", StringComparison.Ordinal) || request.Body.Length != 0)
                throw new ArgumentException("Unsupported publication action.", nameof(request));
            return await ActivateAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException)
        {
            authority.Suspend();
            reconciliationRequired = true;
            throw;
        }
        catch (InvalidDataException)
        {
            authority.Suspend();
            reconciliationRequired = true;
            throw;
        }
        finally
        {
            lock (sync)
                queued--;
            completion.SetResult();
        }
    }

    private async ValueTask<PublicationReply> PrepareAsync(PublicationRequest request, CancellationToken cancellationToken)
    {
        var snapshot = authenticator.Verify(request.Body.Span, request.Signature.Span);
        if (!string.Equals(Identity(request.Body.Span), request.PublicationId, StringComparison.Ordinal))
            throw new ArgumentException("Publication identity differs from its signed body.", nameof(request));
        _ = Replacement(snapshot.ZoneId, codec.Decode(snapshot));
        await CheckFreshnessAsync(snapshot, cancellationToken).ConfigureAwait(false);
        await journal.SaveAsync(request.PublicationId, request.Body, request.Signature, cancellationToken).ConfigureAwait(false);
        var retained = await journal.ReadAsync(request.PublicationId, cancellationToken).ConfigureAwait(false);
        _ = VerifyRetainedProof(retained);
        return Receipt(snapshot, request.PublicationId, "prepared");
    }

    private async ValueTask<PublicationReply> ActivateAsync(PublicationRequest request, CancellationToken cancellationToken)
    {
        authenticator.VerifyActivation(request.PublicationId, request.Signature.Span);
        var proof = await journal.ReadAsync(request.PublicationId, cancellationToken).ConfigureAwait(false);
        var verified = VerifyRetainedProof(proof);
        var decoded = codec.Decode(verified);
        var replacement = Replacement(verified.ZoneId, decoded);
        var current = await CheckFreshnessAsync(verified, cancellationToken).ConfigureAwait(false);
        try
        {
            if (current is null || !Same(current, verified))
                await snapshots.ActivateAsync(verified, cancellationToken).ConfigureAwait(false);
            authority.ReplaceCatalog(replacement.Catalog);
            zones = replacement.Zones;
            generations[verified.ZoneId] = verified;
            await journal.RecordActivationAsync(request.PublicationId, request.Signature, cancellationToken).ConfigureAwait(false);
            var retainedSignature = await journal.ReadActivationSignatureAsync(request.PublicationId, cancellationToken).ConfigureAwait(false);
            authenticator.VerifyActivation(request.PublicationId, retainedSignature);
        }
        catch
        {
            // A final-pointer durability error can follow rename. Do not continue serving an unverified generation.
            authority.Suspend();
            reconciliationRequired = true;
            throw;
        }
        return Receipt(verified, request.PublicationId, "activated");
    }

    private (Dictionary<Guid, AuthoritativeZone> Zones, AuthoritativeCatalog Catalog) Replacement(Guid id, AuthoritativeZone zone)
    {
        var replacement = new Dictionary<Guid, AuthoritativeZone>(zones) { [id] = zone };
        return (replacement, new AuthoritativeCatalog(replacement.Values));
    }

    private ZoneSnapshot VerifyRetainedProof(PublicationRequest proof)
    {
        try
        {
            return authenticator.Verify(proof.Body.Span, proof.Signature.Span);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or ArgumentException or FormatException or CryptographicException)
        {
            throw new InvalidDataException("Retained publication proof no longer matches configured trust.", exception);
        }
    }

    private async ValueTask<ZoneSnapshot?> CheckFreshnessAsync(ZoneSnapshot candidate, CancellationToken cancellationToken)
    {
        var current = await snapshots.ReadActiveAsync(candidate.ZoneId, cancellationToken).ConfigureAwait(false);
        if (generations.TryGetValue(candidate.ZoneId, out var known) && (current is null || !Same(current, known)))
            throw new InvalidDataException("Active storage differs from this process's verified generation; reconciliation is required.");
        if (current is not null && !Same(current, candidate) && (!current.Origin.Equals(candidate.Origin) || candidate.Revision <= current.Revision || !SoaSerial.IsNewer(candidate.Serial, current.Serial)))
            throw new InvalidOperationException("Publication origin, revision or serial is stale.");
        return current;
    }

    private PublicationReply Receipt(ZoneSnapshot snapshot, string id, string state) => new(node, snapshot.ZoneId, snapshot.Revision, snapshot.ContentHash, id, state);
    private static string Identity(ReadOnlySpan<byte> body) => Convert.ToHexStringLower(SHA256.HashData(body));
    private static bool Same(ZoneSnapshot left, ZoneSnapshot right) => left.ZoneId == right.ZoneId && left.Origin.Equals(right.Origin) && left.Revision == right.Revision && left.Serial == right.Serial && string.Equals(left.ContentHash, right.ContentHash, StringComparison.Ordinal);
}
