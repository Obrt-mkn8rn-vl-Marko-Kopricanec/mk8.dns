namespace Mk8.Dns.Domain;

public sealed record ZoneOwnership(Guid TenantId, Guid ZoneId, DnsName Origin);
