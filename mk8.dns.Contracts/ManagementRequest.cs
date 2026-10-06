namespace Mk8.Dns.Contracts;

public sealed record ManagementRequest(string Action, Guid TenantId, Guid ZoneId, Guid OperationId, long ExpectedRevision, ReadOnlyMemory<byte> Origin, IReadOnlyList<ZoneRecordData> Records, ReadOnlyMemory<byte> Credential)
{
    private readonly IReadOnlyList<RrsetChange> changes = Array.Empty<RrsetChange>();
    private readonly IReadOnlyList<RrsetKey> selection = Array.Empty<RrsetKey>();

    public IReadOnlyList<RrsetChange> Changes { get => changes; init => changes = value ?? Array.Empty<RrsetChange>(); }
    public IReadOnlyList<RrsetKey> Selection { get => selection; init => selection = value ?? Array.Empty<RrsetKey>(); }
}
