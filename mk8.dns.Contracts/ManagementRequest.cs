namespace Mk8.Dns.Contracts;

public sealed record ManagementRequest(string Action, Guid TenantId, Guid ZoneId, Guid OperationId, long ExpectedRevision, ReadOnlyMemory<byte> Origin, IReadOnlyList<ZoneRecordData> Records, ReadOnlyMemory<byte> Credential);
