namespace Mk8.Dns.Contracts;

public sealed record ManagementApiRequest(ReadOnlyMemory<byte> Origin)
{
    private readonly IReadOnlyList<ZoneRecordData> records = Array.Empty<ZoneRecordData>();
    private readonly IReadOnlyList<RrsetChange> changes = Array.Empty<RrsetChange>();
    private readonly IReadOnlyList<RrsetKey> selection = Array.Empty<RrsetKey>();

    public long? ExpectedRevision { get; init; }
    public IReadOnlyList<ZoneRecordData> Records { get => records; init => records = value ?? Array.Empty<ZoneRecordData>(); }
    public IReadOnlyList<RrsetChange> Changes { get => changes; init => changes = value ?? Array.Empty<RrsetChange>(); }
    public IReadOnlyList<RrsetKey> Selection { get => selection; init => selection = value ?? Array.Empty<RrsetKey>(); }
}
