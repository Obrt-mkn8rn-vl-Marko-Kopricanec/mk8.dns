namespace Mk8.Dns.Contracts;

public sealed record ManagementReply(Guid OperationId, long Revision, uint Serial, string ContentHash, string State)
{
    private readonly IReadOnlyList<ZoneRecordData> records = Array.Empty<ZoneRecordData>();
    public IReadOnlyList<ZoneRecordData> Records { get => records; init => records = value ?? Array.Empty<ZoneRecordData>(); }
}
