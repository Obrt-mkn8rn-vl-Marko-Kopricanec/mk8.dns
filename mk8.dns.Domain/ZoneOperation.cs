namespace Mk8.Dns.Domain;

public sealed record ZoneOperation(Guid TenantId, Guid OperationId, string Fingerprint, string Actor, string TargetNode, ZoneSnapshot Snapshot, bool Activated);
