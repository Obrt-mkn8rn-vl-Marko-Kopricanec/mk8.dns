using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

internal static class ManagementInput
{
    internal static ManagementRequest Freeze(ManagementRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Credential.Length != 32)
            throw new UnauthorizedAccessException("Management authorization failed.");
        if (request.OperationId == Guid.Empty || request.ExpectedRevision < 0 || request.Origin.Length is 0 or > 255
            || request.Records is not { Count: <= 10_000 } || request.Changes is not { Count: <= 64 } || request.Selection is not { Count: <= 64 })
            throw new ArgumentException("Invalid management request bounds.", nameof(request));
        if (request.Action is not ("edit" or "patch" or "read" or "status" or "import" or "export")
            || request.Action is "edit" && (request.Changes.Count != 0 || request.Selection.Count != 0)
            || request.Action is "patch" && (request.Records.Count != 0 || request.Changes.Count == 0 || request.Selection.Count != 0)
            || request.Action is "read" && (request.Records.Count != 0 || request.Changes.Count != 0 || request.Selection.Count == 0)
            || request.Action is "import" or "export" && (request.Records.Count != 0 || request.Changes.Count != 0 || request.Selection.Count != 0)
            || request.Action is "import" && (request.ZoneFile is not { Length: > 0 and <= ProtocolVersion.MaximumZoneFileBytes }
                || request.ZoneFile.Any(character => character is not (>= ' ' and <= '~' or '\t' or '\r' or '\n')))
            || request.Action is not "import" && request.ZoneFile is not null)
            throw new ArgumentException("Invalid management action fields.", nameof(request));
        foreach (var change in request.Changes)
            ValidateChangeBounds(change);
        RequireByteBound(request);
        var result = request with
        {
            Credential = request.Credential.ToArray(),
            Origin = request.Origin.ToArray(),
            Records = request.Records.Select(FreezeRecord).ToArray(),
            Changes = request.Changes.Select(FreezeChange).ToArray(),
            Selection = request.Selection.Select(key => key is null ? throw new ArgumentException("Empty RRset selection.", nameof(request)) : key with { Owner = CopyOwner(key.Owner) }).ToArray(),
        };
        RequireByteBound(result);
        return result;
    }

    private static void RequireByteBound(ManagementRequest request)
    {
        var size = request.Records.Sum(record => record is null ? throw new ArgumentException("Empty record.", nameof(request)) : (long)record.Owner.Length + record.Data.Length + 10)
            + request.Changes.Sum(change => change.Add.Concat(change.Remove).Sum(data => (long)change.Owner.Length + data.Length + 10));
        if (size > ZoneSnapshot.MaximumPayloadBytes)
            throw new ArgumentException("Management data exceeds the bundle bound.", nameof(request));
    }

    private static ZoneRecordData FreezeRecord(ZoneRecordData record)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(record.Data.Length, ushort.MaxValue, nameof(record));
        return record with { Owner = CopyOwner(record.Owner), Data = record.Data.ToArray() };
    }

    private static RrsetChange FreezeChange(RrsetChange change)
    {
        ValidateChangeBounds(change);
        return change with { Owner = CopyOwner(change.Owner), Add = change.Add.Select(CopyData).ToArray(), Remove = change.Remove.Select(CopyData).ToArray() };
    }

    private static void ValidateChangeBounds(RrsetChange change)
    {
        ArgumentNullException.ThrowIfNull(change);
        if (change.Add is not { Count: <= 256 } || change.Remove is not { Count: <= 256 } || change.Add.Count + change.Remove.Count > 256)
            throw new ArgumentException("An RRset change exceeds its value bound.", nameof(change));
    }

    private static ReadOnlyMemory<byte> CopyOwner(ReadOnlyMemory<byte> owner)
    {
        _ = DnsName.FromWire(owner.Span);
        return owner.ToArray();
    }

    private static ReadOnlyMemory<byte> CopyData(ReadOnlyMemory<byte> data)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(data.Length, ushort.MaxValue, nameof(data));
        return data.ToArray();
    }
}
