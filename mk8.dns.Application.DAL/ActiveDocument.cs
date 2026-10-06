namespace Mk8.Dns.Application.DAL;

internal sealed record ActiveDocument(int FormatVersion, Guid ZoneId, long Revision, string Hash);
