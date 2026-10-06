namespace Mk8.Dns.Application.DAL;

internal sealed record SnapshotDocument(int FormatVersion, Guid ZoneId, string Origin, long Revision, uint Serial, byte[] Payload);
