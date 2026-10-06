namespace Mk8.Dns.Contracts;

public sealed record ManagementReply(Guid OperationId, long Revision, uint Serial, string ContentHash, string State);
