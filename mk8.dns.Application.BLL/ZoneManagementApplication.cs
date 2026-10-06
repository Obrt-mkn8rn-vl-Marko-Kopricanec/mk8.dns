using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

public sealed class ZoneManagementApplication(IControlPlaneStore store, IManagementAuthorizer authorizer, IZoneBundleCodec codec, string targetNode) : IZoneManagement
{
    public async ValueTask<ManagementReply> ExecuteAsync(ManagementRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        request = request with { Credential = request.Credential.ToArray() };
        var actor = authorizer.Authorize(request);
        if (request.OperationId == Guid.Empty || request.ExpectedRevision < 0 || request.Records is null || request.Records.Count > 10_000)
            throw new ArgumentException("Invalid management request bounds.", nameof(request));
        var origin = DnsName.FromWire(request.Origin.Span);
        var action = request.Action;
        if (!string.Equals(action, "edit", StringComparison.Ordinal) && !string.Equals(action, "status", StringComparison.Ordinal))
            throw new ArgumentException("Unsupported management action.", nameof(request));
        AuthoritativeZone? intent = null;
        string? fingerprint = null;
        if (string.Equals(action, "edit", StringComparison.Ordinal))
        {
            intent = new AuthoritativeZone(origin, request.Records.Select(record => new DnsRecord(record.Owner.Span, record.Type, record.Ttl, record.Data.Span)));
            fingerprint = Fingerprint(request, actor, codec.Compile(request.ZoneId, 1, WithSerial(intent, 0)));
        }
        var transaction = await store.BeginAsync(cancellationToken).ConfigureAwait(false);
        await using var lifetime = transaction.ConfigureAwait(false);
        var replay = await transaction.ReadOperationAsync(request.TenantId, request.OperationId, cancellationToken).ConfigureAwait(false);
        if (replay is not null)
        {
            if (replay.Snapshot.ZoneId != request.ZoneId || !replay.Snapshot.Origin.Equals(origin) || fingerprint is not null && !string.Equals(fingerprint, replay.Fingerprint, StringComparison.Ordinal))
                throw new InvalidOperationException("Operation identity was already used for a different intent.");
            return Reply(replay);
        }
        if (intent is null)
            throw new KeyNotFoundException("No authorized operation has this identity.");
        var ownership = await transaction.ReadOwnershipAsync(cancellationToken).ConfigureAwait(false);
        RequireOwnership(ownership, request, origin);
        var current = await transaction.ReadZoneAsync(request.TenantId, request.ZoneId, cancellationToken).ConfigureAwait(false);
        if (current is not null)
            _ = codec.Decode(current);
        if ((current?.Revision ?? 0) != request.ExpectedRevision)
            throw new InvalidOperationException("The expected zone revision is no longer current.");
        var revision = checked(request.ExpectedRevision + 1);
        var serial = current is null ? 1U : SoaSerial.Next(current.Serial);
        var snapshot = codec.Compile(request.ZoneId, revision, WithSerial(intent, serial));
        var operation = new ZoneOperation(request.TenantId, request.OperationId, fingerprint!, actor, targetNode, snapshot, Activated: false);
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

    private string Fingerprint(ManagementRequest request, string actor, ZoneSnapshot intent)
    {
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        writer.Write("M8I1"u8);
        writer.Write(request.TenantId.ToByteArray());
        writer.Write(request.ZoneId.ToByteArray());
        writer.Write(request.ExpectedRevision);
        writer.Write(actor);
        writer.Write(targetNode);
        writer.Write(intent.Origin.ToWire());
        writer.Write(Convert.FromHexString(intent.ContentHash));
        writer.Flush();
        return Convert.ToHexStringLower(SHA256.HashData(output.ToArray()));
    }
}
