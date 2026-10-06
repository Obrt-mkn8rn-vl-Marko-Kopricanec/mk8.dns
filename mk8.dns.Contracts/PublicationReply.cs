namespace Mk8.Dns.Contracts;

public sealed record PublicationReply(string NodeId, Guid ZoneId, long Revision, string ContentHash, string PublicationId, string State);
