using System.Buffers.Binary;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

public sealed class ZoneManagementApplication(IControlPlaneStore store, IManagementAuthorizer authorizer, IZoneBundleCodec codec, string targetNode) : IZoneManagement
{
    public async ValueTask<ManagementReply> ExecuteAsync(ManagementRequest request, CancellationToken cancellationToken)
    {
        request = ManagementInput.Freeze(request);
        var actor = authorizer.Authorize(request);
        var origin = DnsName.FromWire(request.Origin.Span);
        AuthoritativeZone? intent = null;
        RrsetPatch? patch = null;
        string? fingerprint = null;
        if (request.Action is "edit")
        {
            intent = new AuthoritativeZone(origin, request.Records.Select(record => new DnsRecord(record.Owner.Span, record.Type, record.Ttl, record.Data.Span)));
            fingerprint = ManagementFingerprint.Edit(request, actor, targetNode, codec.Compile(request.ZoneId, 1, WithSerial(intent, 0)));
        }
        else if (request.Action is "patch")
        {
            patch = new RrsetPatch(request, origin);
            fingerprint = ManagementFingerprint.Patch(request, actor, targetNode, origin, patch);
        }
        else if (request.Action is "read")
            RrsetSelection.Validate(request, origin);
        var transaction = await store.BeginAsync(cancellationToken).ConfigureAwait(false);
        await using var lifetime = transaction.ConfigureAwait(false);
        if (!string.Equals(actor, authorizer.Authorize(request), StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Management principal changed during admission.");
        if (request.Action is "read")
            return await ReadAsync(transaction, request, cancellationToken).ConfigureAwait(false);
        var replay = await transaction.ReadOperationAsync(request.TenantId, request.OperationId, cancellationToken).ConfigureAwait(false);
        if (replay is not null)
        {
            authorizer.AuthorizeOperation(request, replay.Actor);
            if (replay.Snapshot.ZoneId != request.ZoneId || !replay.Snapshot.Origin.Equals(origin) || fingerprint is not null && !string.Equals(fingerprint, replay.Fingerprint, StringComparison.Ordinal))
                throw new InvalidOperationException("Operation identity was already used for a different intent.");
            return Reply(replay);
        }
        if (request.Action is "status")
            throw new KeyNotFoundException("No authorized operation has this identity.");
        return await CommitAsync(transaction, request, actor, origin, intent, patch, fingerprint!, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<ManagementReply> ReadAsync(IControlTransaction transaction, ManagementRequest request, CancellationToken cancellationToken)
    {
        var current = await transaction.ReadZoneAsync(request.TenantId, request.ZoneId, cancellationToken).ConfigureAwait(false)
            ?? throw new KeyNotFoundException("No authorized zone has this identity.");
        var zone = codec.Decode(current);
        authorizer.AuthorizeZone(request, zone);
        return new ManagementReply(request.OperationId, current.Revision, current.Serial, current.ContentHash, "current") { Records = RrsetSelection.Read(zone, request) };
    }

    private async ValueTask<ManagementReply> CommitAsync(IControlTransaction transaction, ManagementRequest request, string actor, DnsName origin, AuthoritativeZone? intent, RrsetPatch? patch, string fingerprint, CancellationToken cancellationToken)
    {
        var ownership = await transaction.ReadOwnershipAsync(cancellationToken).ConfigureAwait(false);
        RequireOwnership(ownership, request, origin);
        var current = await transaction.ReadZoneAsync(request.TenantId, request.ZoneId, cancellationToken).ConfigureAwait(false);
        var currentZone = current is null ? null : codec.Decode(current);
        if (patch is not null)
        {
            if (currentZone is null)
                throw new KeyNotFoundException("RRset changes require an existing authorized zone.");
            authorizer.AuthorizeZone(request, currentZone);
            intent = patch.Apply(currentZone);
        }
        if ((current?.Revision ?? 0) != request.ExpectedRevision)
            throw new InvalidOperationException("The expected zone revision is no longer current.");
        var revision = checked(request.ExpectedRevision + 1);
        var serial = current is null ? 1U : SoaSerial.Next(current.Serial);
        var snapshot = codec.Compile(request.ZoneId, revision, WithSerial(intent!, serial));
        var operation = new ZoneOperation(request.TenantId, request.OperationId, fingerprint, actor, targetNode, snapshot, Activated: false);
        if (!string.Equals(actor, authorizer.Authorize(request), StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Management principal changed during admission.");
        await transaction.AppendAsync(operation, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return Reply(operation);
    }

    private static void RequireOwnership(IReadOnlyList<ZoneOwnership> ownership, ManagementRequest request, DnsName origin)
    {
        var owned = ownership.FirstOrDefault(item => item.ZoneId == request.ZoneId);
        if (owned is not null && (owned.TenantId != request.TenantId || !owned.Origin.Equals(origin))
            || owned is null && (ownership.Count >= 64 || ownership.Any(item => item.Origin.IsSubdomainOf(origin) || origin.IsSubdomainOf(item.Origin))))
            throw new InvalidOperationException("Zone identity or origin conflicts with existing ownership.");
    }

    private static ManagementReply Reply(ZoneOperation operation) => new(operation.OperationId, operation.Snapshot.Revision, operation.Snapshot.Serial, operation.Snapshot.ContentHash, operation.Activated ? "activated" : "accepted");

    private static AuthoritativeZone WithSerial(AuthoritativeZone zone, uint serial)
    {
        var data = zone.Soa.GetData();
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(data.Length - 20), serial);
        var soa = new DnsRecord(zone.Soa.GetOwnerWire(), 6, zone.Soa.Ttl, data);
        return new AuthoritativeZone(zone.Origin, zone.GetAllRecords().Select(record => record.Type == 6 ? soa : record));
    }

}
